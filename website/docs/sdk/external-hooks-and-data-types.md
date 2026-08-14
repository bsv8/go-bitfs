---
id: external-hooks-and-data-types
title: 02 · External hooks and data types
---

# 02 · External hooks and data types

Return to the [SDK API framework](sdk-api-framework-design.md).

Applications inject wallet, persistence, content, and node capabilities into the SDK. The SDK does not require a particular database or RPC service.

## Signing, time, and content hooks

```go
// package pool
// Signer exposes one role's public key and detached signatures. The SDK never
// receives or stores the private key.
type Signer interface {
    PublicKey(ctx context.Context) ([]byte, error)
    Sign(ctx context.Context, payload []byte) ([]byte, error)
}

// package pool
// SignatureVerifier is the generic detached-signature verifier used by pool
// adapters. Buyer and seller workflows use the bitfs verifier function types
// below instead.
type SignatureVerifier interface {
    Verify(pubkey, payload, signature []byte) error
}

// package bitfs
type QuoteTermsSignatureVerifier func(sellerPubkey, termsCBOR, signature []byte) error
type ContentTermsSignatureVerifier func(pubkey, termsCBOR, signature []byte) error

// package buyer
type ContentSink interface {
    SaveVerifiedContent(ctx context.Context, hash bitfs.Hash32, payload []byte) error
}

type SeedSource interface {
    LoadSeed(ctx context.Context, seedHash masterseed.Digest) ([]byte, error)
}

// package seller
// ContentSource returns raw seed or block bytes by content hash. The SDK still
// verifies the returned hash and length.
type ContentSource interface {
    LoadSeed(ctx context.Context, seedHash masterseed.Digest) ([]byte, error)
    LoadBlock(ctx context.Context, blockHash masterseed.Digest) ([]byte, error)
}
```

Buyer and seller workflows use `Clock func() time.Time` in their respective
`WorkflowConfig` values; there is no SDK `Clock` interface in the current API.

## Storage hooks

Storage interfaces are separated by credential category. An application may implement all of them with one database or use files and memory independently.

```go
// package buyer; package seller
// Each role package declares this same small QuoteStore interface locally.
type QuoteStore interface {
    SaveQuote(ctx context.Context, quote *bitfs.SignedFileQuote) error
    LoadQuote(ctx context.Context, termsHash bitfs.Hash32) (*bitfs.SignedFileQuote, error)
}

// package pool
// PoolStore retains complete opening proofs, node-accepted payment states,
// health/reconciliation state, and the funding-ID lookup used by the seller.
type PoolStore interface {
    OpeningProofStore
    LoadOpeningProofByFundingTxID(context.Context, Hash32) (*OpeningProof, error)
    SaveAcceptedPayment(context.Context, *PaymentState) error
    LoadAcceptedPayment(context.Context, Hash32) (*PaymentState, error)
    EnsurePoolHealthy(context.Context, Hash32) error
    MarkExternalStateUncertain(context.Context, Hash32, Hash32) error
    ReconcileExternalState(context.Context, Hash32, *PaymentState) error
}

// package pool
// PendingRequestStore atomically manages the seller-side delivery lease.
type PendingRequestStore interface {
    TryAcquire(context.Context, PendingRequest) (PendingAcquireResult, error)
    Load(context.Context, Hash32) (*PendingRequest, error)
    Release(context.Context, Hash32, Hash32) error
}
```

`bitfs.FileQuoteStore` implements the role-local quote store. `pool.MemoryStore`
and `pool.FileStore` implement `pool.PoolStore` and
`pool.PendingRequestStore` for the supported storage modes.

`pool.MemoryStore` is intended for tests and temporary single-process use. `pool.FileStore` reloads under an advisory lock and atomically snapshots opening proofs, latest payment states, and `ExpectedSellerAmountSat`; it can serialize cooperating Unix processes. Replace it with a database for stronger transactional or distributed guarantees.

## BSV node and transaction hooks

Ordinary broadcast and non-final updates have different semantics and therefore use different methods. This prevents an application from treating a successful HTTP request as proof that pool state advanced.

```go
// package pool
type BuyerPoolPort interface {
    TransactionID([]byte) (Hash32, error)
    BuildRefundPresignRequest(context.Context, OpeningInput, Signer) (*RefundPresignRequest, error)
    BuildRefundSubmission(*OpeningProof) ([]byte, error)
    VerifyRefundExpired(*OpeningProof, time.Time) error
    VerifyOpening(*OpeningProof) error
    ParsePaymentState(context.Context, []byte, *OpeningProof) (*PaymentState, error)
    ParseUnsignedPayment(context.Context, []byte, *OpeningProof) (*UnsignedPayment, error)
    VerifyAcceptedPayment(*PaymentState, *OpeningProof) error
    VerifyBuyerPayment(*UnsignedPayment, []byte, *OpeningProof) error
    VerifyCompletedFinalPayment(*SignedPayment, *OpeningProof) error
    CheckPaymentCapacity(context.Context, PaymentUpdateInput) error
    BuildPaymentUpdate(context.Context, PaymentUpdateInput) (*UnsignedPayment, error)
    SignBuyerPayment(context.Context, *UnsignedPayment, Signer) ([]byte, error)
    BuildImmediateClose(context.Context, CloseInput) (*UnsignedPayment, []byte, error)
}

// package pool
type SellerPoolPort interface {
    TransactionID([]byte) (Hash32, error)
    FundingTxID([]byte) (Hash32, error)
    BuildRefundSubmission(*OpeningProof) ([]byte, error)
    VerifyOpening(*OpeningProof) error
    ParsePaymentState(context.Context, []byte, *OpeningProof) (*PaymentState, error)
    ParseUnsignedPayment(context.Context, []byte, *OpeningProof) (*UnsignedPayment, error)
    VerifyAcceptedPayment(*PaymentState, *OpeningProof) error
    VerifyArbitratedPayment(*PaymentState, *OpeningProof) error
    VerifyBuyerPayment(*UnsignedPayment, []byte, *OpeningProof) error
    VerifySellerPayment(*UnsignedPayment, []byte, *OpeningProof) error
    CheckPaymentCapacity(context.Context, PaymentUpdateInput) error
    BuildPaymentUpdate(context.Context, PaymentUpdateInput) (*UnsignedPayment, error)
    SignSellerArbitrationCandidate(context.Context, *UnsignedPayment, Signer) ([]byte, error)
    SignSellerPayment(context.Context, *UnsignedPayment, Signer) ([]byte, error)
    MergeBuyerSellerPayment(*UnsignedPayment, []byte, []byte) (*SignedPayment, error)
    MergeSellerArbiterPayment(*UnsignedPayment, []byte, []byte) (*SignedPayment, error)
    SignImmediateClose(context.Context, *UnsignedPayment, []byte, Signer) (*SignedPayment, error)
}

// package arbitration
type PoolPort interface {
    VerifyOpening(*pool.OpeningProof) error
    VerifyArbitrationCandidate(context.Context, []byte, *pool.OpeningProof, *bitfs.ContentRequestTerms, []byte) (*pool.UnsignedPayment, error)
    SignArbitrationCandidate(context.Context, []byte, *pool.OpeningProof, pool.Signer) ([]byte, error)
}

// package pool
type NonFinalPoolNode interface {
    SubmitUpdate(context.Context, []byte) (*UpdateAcceptance, error)
    SubmitFinal(context.Context, []byte) (Hash32, error)
}
```

The concrete `pool.MultisigPoolEngine` adapters use a role-specific
`PrivateKeyProvider` for transaction sighashes. That is separate from the
workflow credential `Signer`.

`pool.VerifiedNonFinalPoolNode` is the supplied node adapter. Before calling an external backend it parses and verifies non-final updates, final two-signature transactions, or expired refunds; afterward it checks the returned transaction ID, `SpendTxID`, and sequence.

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
    QuoteTermsHash        bitfs.Hash32     // A quote previously accepted by AcceptQuote.
    Pool                  pool.Reference   // A valid pool and its current sequence.
    SelectedArbiterPubKey []byte           // Allowed by the quote and equal to the pool arbiter.
    Content               bitfs.ContentRef // Seed or Block plus its content hash.
    ContentSize           uint64           // Expected payload size used for pricing.
    DeliveryDeadline      bitfs.UnixSeconds // Latest delivery time accepted by the buyer.
}

// OpeningInput is passed to the pool layer after the buyer wallet prepares a
// signed, unpublished FundingTx. PoolOutputIndex selects its 2-of-3 output.
type OpeningInput struct {
    FundingTx       []byte
    PoolOutputIndex uint32
    ExpiryLockTime       uint32
    MinerFeeRateSatPerKB uint64
    SellerPubKey         []byte
    ArbiterPubKey        []byte
}

// PaymentUpdateInput is the low-level generic-pool input. buyer.Workflow does
// not expose SellerAmountAfterSat; it derives that value from 001, 003, and 004.
type PaymentUpdateInput struct {
    Opening              *OpeningProof // Complete evidence, not a database ID.
    Previous             *PaymentState // Latest state; initially the refund state.
    PaymentSequenceAfter uint32        // Greater than Previous and below 0xffffffff.
    SellerAmountAfterSat uint64        // Absolute cumulative amount, not an increment.
}

// CloseInput is only for negotiated immediate close. SellerAmountAfterSat
// normally equals the last accepted cumulative amount and is not repriced here.
type CloseInput struct {
    Opening              *OpeningProof
    Latest               *PaymentState
    SellerAmountAfterSat uint64
}
```
