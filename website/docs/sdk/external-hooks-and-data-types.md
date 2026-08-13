---
id: external-hooks-and-data-types
title: 02 · External hooks and data types
---

# 02 · External hooks and data types

Return to the [SDK API framework](sdk-api-framework-design.md).

Applications inject wallet, persistence, content, and node capabilities into the SDK. The SDK does not require a particular database or RPC service.

## Signing, time, and content hooks

```go
// Signer signs exact bytes with an application-managed private key. The SDK
// never receives or stores the private key.
type Signer interface {
    PublicKey(ctx context.Context) ([]byte, error)
    Sign(ctx context.Context, payload []byte) ([]byte, error)
}

// SignatureVerifier checks a signature by a public key over the exact payload.
// 001, 003, and 004 use it; 005 uses MultisigPoolPort transaction checks.
type SignatureVerifier interface {
    Verify(pubkey, payload, signature []byte) error
}

// Clock makes deadline checks testable and keeps workflows from calling
// time.Now directly.
type Clock interface {
    NowUnix() UnixSeconds
}

// ContentSource is implemented only by sellers. It returns raw seed or block
// bytes by content hash; the SDK still verifies their hash and length.
type ContentSource interface {
    LoadContent(ctx context.Context, hash Hash32) ([]byte, error)
}

// SeedSource is implemented only by buyers. For block requests it provides a
// verified seed so the SDK can check seed_hash and block-hash membership.
type SeedSource interface {
    LoadSeed(ctx context.Context, seedHash Hash32) ([]byte, error)
}

// ContentSink is an optional buyer persistence hook called only after 004 has
// passed every validation step.
type ContentSink interface {
    SaveVerifiedContent(ctx context.Context, hash Hash32, payload []byte) error
}
```

## Storage hooks

Storage interfaces are separated by credential category. An application may implement all of them with one database or use files and memory independently.

```go
// QuoteStore retains verified 001 credentials. Sellers use the original quote
// to validate 003; buyers use it to validate 004 and price 005.
type QuoteStore interface {
    SaveQuote(ctx context.Context, quote *bitfs.SignedFileQuote) error
    LoadQuote(ctx context.Context, termsHash Hash32) (*bitfs.SignedFileQuote, error)
}

// PoolStore retains complete opening proofs and the latest node-accepted
// payment. SpendTxID is the stable initial deferred-spend ID, not an update ID.
type PoolStore interface {
    SaveOpeningProof(ctx context.Context, proof *pool.OpeningProof) error
    LoadOpeningProof(ctx context.Context, spendTxID Hash32) (*pool.OpeningProof, error)
    SaveAcceptedPayment(ctx context.Context, payment *pool.PaymentState) error
    LoadAcceptedPayment(ctx context.Context, spendTxID Hash32) (*pool.PaymentState, error)
}

// package pool
// PendingRequest is the durable seller-side single-request latch. It protects
// delivery; it is not payment ground truth. ExpectedSellerAmountSat is the
// exact increment derived after validating 001, 003, and seed membership.
type PendingRequest struct {
    SpendTxID               Hash32 // Stable initial deferred-spend transaction ID.
    BasePaymentSequence     uint32 // Latest nSequence when the seller accepted 003.
    ContentRequestHash      Hash32 // Terms hash that 005 must reference.
    ExpectedSellerAmountSat uint64 // Exact seller cumulative-amount increment.
}

// PendingRequestStore atomically checks current state and writes the latch.
// TryAcquire returns PendingAcquired, PendingAlreadyHeld, or PendingConflict;
// the latter two MUST prevent delivery side effects.
type PendingRequestStore interface {
    TryAcquire(ctx context.Context, pending pool.PendingRequest) (result pool.PendingAcquireResult, err error)
    Load(ctx context.Context, spendTxID Hash32) (*pool.PendingRequest, error)
    Release(ctx context.Context, spendTxID Hash32, requestHash Hash32) error
}
```

`bitfs.FileQuoteStore` uses an advisory lock and atomic snapshots. On Unix it serializes processes that follow the same lock-file convention. Use a database when stronger transactions, indexes, or cluster locking are required. It stores the complete signed quote under its normalized `FileQuoteTermsHash`.

`pool.MemoryStore` is intended for tests and temporary single-process use. `pool.FileStore` reloads under an advisory lock and atomically snapshots opening proofs, latest payment states, and `ExpectedSellerAmountSat`; it can serialize cooperating Unix processes. Replace it with a database for stronger transactional or distributed guarantees.

## BSV node and transaction hooks

Ordinary broadcast and non-final updates have different semantics and therefore use different methods. This prevents an application from treating a successful HTTP request as proof that pool state advanced.

```go
// MultisigPoolPort converts business values to canonical MultisigPool calls.
// It neither accesses the network nor stores state.
type MultisigPoolPort interface {
    TransactionID(rawTx []byte) (Hash32, error)
    VerifyOpening(proof *pool.OpeningProof) error
    ParseFinalPaymentState(ctx context.Context, rawTx []byte, proof *pool.OpeningProof) (*pool.PaymentState, error)
    VerifyAcceptedPayment(state *pool.PaymentState, proof *pool.OpeningProof) error
    BuildRefundSubmission(proof *pool.OpeningProof) ([]byte, error)
    BuildPaymentUpdate(ctx context.Context, input pool.PaymentUpdateInput) (*pool.UnsignedPayment, error)
    SignBuyerPayment(ctx context.Context, payment *pool.UnsignedPayment, buyer Signer) ([]byte, error)
    VerifyBuyerPayment(payment *pool.UnsignedPayment, signature []byte, proof *pool.OpeningProof) error
    SignSellerPayment(ctx context.Context, payment *pool.UnsignedPayment, seller Signer) ([]byte, error)
    MergeBuyerSellerPayment(payment *pool.UnsignedPayment, buyerSignature, sellerSignature []byte) (*pool.SignedPayment, error)
    VerifyArbitratedPayment(state *pool.PaymentState, proof *pool.OpeningProof) error
    MergeSellerArbiterPayment(payment *pool.UnsignedPayment, sellerSignature, arbiterSignature []byte) (*pool.SignedPayment, error)
    BuildImmediateClose(ctx context.Context, input pool.CloseInput) (*pool.UnsignedPayment, []byte, error)
    VerifyFinalPayment(state *pool.PaymentState, proof *pool.OpeningProof) error
    VerifyCompletedFinalPayment(payment *pool.SignedPayment, proof *pool.OpeningProof) error
}

// NonFinalPoolNode is the dedicated BSV non-final transaction-pool port.
// SubmitUpdate returns nil only after the node confirms acceptance of a higher
// nSequence for the same input.
type NonFinalPoolNode interface {
    SubmitUpdate(ctx context.Context, rawSignedTx []byte) (*pool.UpdateAcceptance, error)
    SubmitFinal(ctx context.Context, rawSignedTx []byte) (txid Hash32, err error)
}
```

`pool.VerifiedNonFinalPoolNode` is the supplied node adapter. Before calling an external backend it parses and verifies non-final updates, final two-signature transactions, or expired refunds; afterward it checks the returned transaction ID, `SpendTxID`, and sequence. A concrete BSV RPC or SDK is injected through `pool.NonFinalPoolBackend`; this repository assumes no vendor-specific path or response format.

`UpdateAcceptance` includes the accepted transaction ID, `SpendTxID` anchor, and accepted `nSequence`. A node that reports only “received” without a state-acceptance guarantee cannot implement this interface correctly.

## Key input types

Workflows do not ask applications to repeat fields derivable from credentials. The following types contain the small set of choices or values the caller must supply.

```go
// package pool
// Reference identifies the stable pool selected by 003. SpendTxID is always
// the initial deferred-spend ID, never an update transaction ID.
type Reference struct {
    SpendTxID           Hash32
    BasePaymentSequence uint32 // Latest nSequence observed by the buyer.
}

// package buyer
// ContentRequestInput is the buyer's business choice for 003. Price, block
// index, seller amount, and filename are derived from retained evidence.
type ContentRequestInput struct {
    QuoteTermsHash        Hash32           // A quote previously accepted by AcceptQuote.
    Pool                  pool.Reference   // A valid pool and its current sequence.
    SelectedArbiterPubKey []byte           // Allowed by the quote and equal to the pool arbiter.
    Content               bitfs.ContentRef // Seed or Block plus its content hash.
    DeliveryDeadline      UnixSeconds      // Latest delivery time accepted by the buyer.
}

// OpeningInput is passed to the pool layer after the buyer wallet prepares a
// signed, unpublished FundingTx. PoolOutputIndex selects its 2-of-3 output.
type OpeningInput struct {
    FundingTx       []byte
    PoolOutputIndex uint32
    ExpiryLockTime  uint32 // <500000000 is height; otherwise Unix time.
    MinerFeeRateSatPerKB uint64 // Fixed integer fee rate for every pool state.
    SellerPubKey    []byte
    ArbiterPubKey   []byte
}

// PaymentUpdateInput is the low-level generic-pool input. buyer.Workflow does
// not expose SellerAmountAfterSat; it derives that value from 001, 003, and 004.
type PaymentUpdateInput struct {
    Opening              *OpeningProof // Complete evidence, not a database ID.
    Previous             *PaymentState // Latest state; initially the refund state.
    PaymentSequenceAfter uint32        // Greater than Previous and below 0xffffffff.
    SellerAmountAfterSat uint64        // Absolute cumulative amount, not an increment.
    MinerFeeRateSatPerKB uint64        // The opening's fixed integer fee rate.
}

// CloseInput is only for negotiated immediate close. SellerAmountAfterSat
// normally equals the last accepted cumulative amount and is not repriced here.
type CloseInput struct {
    Opening              *OpeningProof
    Latest               *PaymentState
    SellerAmountAfterSat uint64
    MinerFeeRateSatPerKB uint64
}
```
