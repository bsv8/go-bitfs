---
id: role-workflow-api
title: 03 · Role workflow API
---

# 03 · Role workflow API

Return to the [SDK API framework](sdk-api-framework-design.md).

The implemented entry points are `buyer.NewWorkflow(buyer.WorkflowConfig{...})`, `seller.NewWorkflow(seller.WorkflowConfig{...})`, and `arbitration.NewWorkflow(arbitration.WorkflowConfig{...})`. The signatures below explain role-level call order; the actual package declarations remain authoritative.

These facades do not own network connections. Each method returns a structured message or raw transaction for the application to send to the next participant. See [External hooks and data types](external-hooks-and-data-types.md) for signing, storage, and node dependencies.

## Buyer API

```go
// package buyer
type Workflow struct { /* unexported fields */ }

type WorkflowConfig struct {
    Signer            pool.Signer
    QuoteVerifier     bitfs.QuoteTermsSignatureVerifier
    SignatureVerifier bitfs.ContentTermsSignatureVerifier
    Clock             func() time.Time
    Quotes            QuoteStore
    Pools             pool.PoolStore
    Opening           pool.BuyerPoolOpeningHooks
    Participants      pool.ParticipantVerifier
    Node              pool.NonFinalPoolNode
    Transactions      pool.BuyerPoolPort
    ContentSink       ContentSink
    SeedSource        SeedSource
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error)

// AcceptQuote verifies 001 and stores the raw quote so later operations can
// recover it by hash.
func (workflow *buyer.Workflow) AcceptQuote(
    ctx context.Context,
    quote *bitfs.SignedFileQuote,
) (*bitfs.FileQuoteTerms, error)

// PreparePoolOpening accepts a wallet-prepared FundingTx, builds the initial
// deferred RefundTx, and signs the buyer side. Send the returned 002 request
// to the seller; the FundingTx MUST NOT be broadcast yet.
func (workflow *buyer.Workflow) PreparePoolOpening(
    ctx context.Context,
    input pool.OpeningInput,
) (*pool.RefundPresignRequest, error)

// AcceptRefundPresign verifies the seller refund signature, stores the full
// opening proof, and records the initial refund state. The seller may not yet
// have submitted the FundingTx.
func (workflow *buyer.Workflow) AcceptRefundPresign(
    ctx context.Context,
    request *pool.RefundPresignRequest,
    response *pool.RefundPresignResponse,
    fundingTx []byte,
) (*pool.Reference, error)

// BuildFundingTxDelivery creates the final 002 message after the buyer has
// durably stored the complete opening proof.
func (workflow *buyer.Workflow) BuildFundingTxDelivery(
    fundingTx []byte,
) (*pool.FundingTxDelivery, error)

// RequestContent selects a verified quote, usable pool, and content hash and
// creates 003 from the latest locally accepted pool state.
func (workflow *buyer.Workflow) RequestContent(
    ctx context.Context,
    input ContentRequestInput,
) (*bitfs.SignedContentRequest, error)

// AcceptDelivery verifies and optionally stores 004, then prices and signs
// 005. Send the PaymentUpdate to the seller; this method does not submit it.
func (workflow *buyer.Workflow) AcceptDelivery(
    ctx context.Context,
    request *bitfs.SignedContentRequest,
    delivery *bitfs.SignedContentDelivery,
) (*pool.PaymentUpdate, error)

// RefundAfterExpiry merges the separately retained opening signatures into a
// refund and submits it. A node may reject it if a newer payment state exists.
func (workflow *buyer.Workflow) RefundAfterExpiry(ctx context.Context, spendTxID pool.Hash32) (pool.Hash32, error)

// BuildImmediateClose creates an unsigned negotiated-close transaction and a
// detached buyer signature. Both nSequence and nLockTime are 0xffffffff; this
// is not the unilateral expiry-refund path.
func (workflow *buyer.Workflow) BuildImmediateClose(
    ctx context.Context,
    input pool.CloseInput,
) (*pool.UnsignedPayment, []byte, error)

// SubmitImmediateClose submits the final transaction after the seller has
// added its signature. It does not overwrite non-final pool state.
func (workflow *buyer.Workflow) SubmitImmediateClose(
    ctx context.Context,
    close *pool.SignedPayment,
) (pool.Hash32, error)
```

`ContentRequestInput` includes a verified quote, a `pool.Reference` containing `SpendTxID` and the current `BasePaymentSequence`, the selected arbiter key, `ContentRef`, and a delivery deadline. It does not accept a block index, quote price, or arbitrary seller amount.

## Seller API

The seller API encloses the risky “deliver first, receive payment later” window in one operation: validate 003, atomically acquire the latch, then load and sign 004. Callers MUST NOT bypass `DeliverRequestedContent` to deliver content directly.

```go
// package seller
type WorkflowConfig struct {
    Signer            pool.Signer
    SignatureVerifier bitfs.ContentTermsSignatureVerifier
    QuoteVerifier     bitfs.QuoteTermsSignatureVerifier
    Clock             func() time.Time
    Quotes            QuoteStore
    Pools             pool.PoolStore
    OpeningHooks      pool.SellerPoolOpeningHooks
    Pending           pool.PendingRequestStore
    Content           ContentSource
    Transactions      pool.SellerPoolPort
    Participants      pool.ParticipantVerifier
    Node              pool.NonFinalPoolNode
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error)

// CreateQuote creates, signs, and stores 001 for delivery over any application transport.
func (workflow *seller.Workflow) CreateQuote(
    ctx context.Context,
    draft bitfs.FileQuoteTerms,
    recommendedFilename string,
) (*bitfs.SignedFileQuote, error)

// PresignPoolOpening validates 002, signs its initial refund transaction, and
// stores a pending opening proof. The response alone does not fund the pool.
func (workflow *seller.Workflow) PresignPoolOpening(
    ctx context.Context,
    request *pool.RefundPresignRequest,
) (*pool.RefundPresignResponse, error)

// AcceptPoolFunding checks FundingTx against the pending proof, stores the
// complete proof, and submits FundingTx. Only successful submission makes the
// pool usable for 003.
func (workflow *seller.Workflow) AcceptPoolFunding(
    ctx context.Context,
    delivery *pool.FundingTxDelivery,
) (*pool.OpeningProof, error)

// DeliverRequestedContent verifies 003, its quote, pool, participants,
// balance, and current sequence. It atomically acquires the pool latch before
// loading and signing content. Existing work returns ErrPoolBusy; a non-current
// sequence returns ErrStalePaymentSequence.
func (workflow *seller.Workflow) DeliverRequestedContent(
    ctx context.Context,
    request *bitfs.SignedContentRequest,
) (*bitfs.SignedContentDelivery, error)

// AcceptPayment verifies the 005 raw transaction, buyer signature, input,
// increasing nSequence, and cumulative amount. It adds the seller signature,
// submits to the non-final pool, and stores the new state and releases the
// latch only after node acceptance.
func (workflow *seller.Workflow) AcceptPayment(
    ctx context.Context,
    payment *pool.PaymentUpdate,
) (*pool.PaymentState, error)

// SignImmediateClose checks an unsigned close and detached buyer signature,
// uses the workflow's configured seller signer to add the seller signature,
// and returns a complete transaction without broadcasting it. The signer
// parameter is retained for interface compatibility.
func (workflow *seller.Workflow) SignImmediateClose(
    ctx context.Context,
    close *pool.UnsignedPayment,
    buyerSignature []byte,
    signer pool.Signer,
) (*pool.SignedPayment, error)

// BuildArbitrationRequestFromAuthorization constructs an unsigned candidate from final 003
// authorization and the current state and adds the seller signature.
func (workflow *seller.Workflow) BuildArbitrationRequestFromAuthorization(
    ctx context.Context,
    proof *pool.OpeningProof,
    authorization *bitfs.SignedContentRequest,
    latest *pool.PaymentState,
) (*arbitration.ArbitrationRequest, error)

// SubmitArbitratedPayment merges the arbiter signature and submits that same
// cumulative state through the non-final node.
func (workflow *seller.Workflow) SubmitArbitratedPayment(
    ctx context.Context,
    request *arbitration.ArbitrationRequest,
    response *arbitration.ArbitrationResponse,
) (*pool.PaymentState, error)
```

## Arbiter API

The arbiter receives complete evidence instead of querying buyer or seller state. It does not decide whether content was delivered or recalculate quote amounts.

```go
// package arbitration
type WorkflowConfig struct {
    Signer                pool.Signer
    Pool                  PoolPort
    AuthorizationVerifier bitfs.ContentTermsSignatureVerifier
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error)

// Application-local adapter, not an SDK type. The seller application may
// implement this transport over HTTP, a queue, or a local call.
type ArbiterClient interface {
    SignPayment(ctx context.Context, request *arbitration.ArbitrationRequest) (*arbitration.ArbitrationResponse, error)
}

// SignPayment checks the complete opening proof, final authorization, and
// unsigned candidate. It returns only the arbiter signature for those exact
// bytes, not an approval state, amount, or database ID.
func (workflow *arbitration.Workflow) SignPayment(
    ctx context.Context,
    request *arbitration.ArbitrationRequest,
) (*arbitration.ArbitrationResponse, error)
```

## Complete business flow

The following end-to-end example walks through one buyer purchasing a file from a seller. It is application-level pseudocode: the wallet, stores, content source, MultisigPool adapters, and node adapters are implemented by the application and injected into the SDK.

### 1. Create one capability set for each role

A `Signer` represents one role and one private key. A verifier has no role key of its own; the SDK supplies the public key being checked from the quote, the 003 authorization, or the opening proof.

```go
buyerSigner   := app.BuyerSigner()   // implements pool.Signer
sellerSigner  := app.SellerSigner()  // implements pool.Signer
arbiterSigner := app.ArbiterSigner() // implements pool.Signer

// These callbacks implement the underlying signature scheme. The pubkey is
// supplied by the credential being verified; the verifier has no role key.
verifyQuote := app.VerifyQuote       // bitfs.QuoteTermsSignatureVerifier
verifyTerms := app.VerifyTerms       // bitfs.ContentTermsSignatureVerifier

buyerWorkflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{
    Signer:            buyerSigner,
    QuoteVerifier:     verifyQuote,
    SignatureVerifier: verifyTerms,
    Clock:             time.Now,
    Quotes:            buyerQuotes,
    Pools:             buyerPools,
    Opening:           buyerOpeningHooks,
    Participants:      participantVerifier,
    Transactions:      buyerPoolPort,
    Node:              buyerNode,
    ContentSink:       buyerContentSink,
    SeedSource:        buyerSeedSource,
})
must(err)

sellerWorkflow, err := seller.NewWorkflow(seller.WorkflowConfig{
    Signer:            sellerSigner,
    QuoteVerifier:     verifyQuote,
    SignatureVerifier: verifyTerms,
    Clock:             time.Now,
    Quotes:            sellerQuotes,
    Pools:             sellerPools,
    OpeningHooks:      sellerOpeningHooks,
    Pending:           sellerPending,
    Content:           sellerContent,
    Transactions:      sellerPoolPort,
    Participants:      participantVerifier,
    Node:              sellerNode,
})
must(err)

arbiterWorkflow, err := arbitration.NewWorkflow(arbitration.WorkflowConfig{
    Signer:                arbiterSigner,
    Pool:                  arbiterPoolPort,
    AuthorizationVerifier: verifyTerms,
})
must(err)
```

The application transport carries only the route `Kind` and the original CBOR bytes. This helper represents that rule; a real application can place the result in HTTP, WebSocket, a queue, or local RPC.

```go
func makePacket(kind wire.Kind, value any) wire.Packet {
    packet, err := wire.Marshal(kind, value)
    must(err)
    return packet
}

func transmit(packet wire.Packet) (wire.Kind, []byte) {
    // Send both values through the application transport. The receiver uses
    // the Kind to select the matching typed Unmarshal helper.
    return packet.Kind, append([]byte(nil), packet.CBOR...)
}
```

### 2. The seller creates a quote and the buyer accepts it

```go
quote, err := sellerWorkflow.CreateQuote(ctx, quoteDraft, "report.pdf")
must(err)

_, quoteCBOR := transmit(makePacket(wire.Quote, quote))
receivedQuote, err := wire.UnmarshalQuote(quoteCBOR)
must(err)

quoteTerms, err := buyerWorkflow.AcceptQuote(ctx, receivedQuote)
must(err)
quoteHashRaw, err := bitfs.FileQuoteTermsHash(receivedQuote.TermsCBOR)
must(err)
quoteHash := bitfs.Hash32(quoteHashRaw)
_ = quoteTerms // Verified terms; later requests refer to them by quoteHash.
```

Two different actions occur here: the seller's `Signer` signs the quote, and the buyer's `QuoteVerifier` verifies the `SellerPubkey` carried by the quote. The buyer never needs the seller's private key.

### 3. The buyer and seller open the payment pool

`fundingTx` is the raw funding transaction prepared by the buyer's wallet. The refund transaction must be presigned before the funding transaction is broadcast.

```go
arbiterPubkey, err := arbiterSigner.PublicKey(ctx)
must(err)

fundingTx := app.BuildFundingTx()
presign, err := buyerWorkflow.PreparePoolOpening(ctx, pool.OpeningInput{
    FundingTx:            fundingTx,
    PoolOutputIndex:      0,
    ExpiryLockTime:       app.RefundExpiryLockTime(),
    MinerFeeRateSatPerKB: app.MinerFeeRate(),
    SellerPubKey:         receivedQuote.SellerPubkey,
    ArbiterPubKey:        arbiterPubkey,
})
must(err)

_, sellerPresignCBOR := transmit(makePacket(wire.PoolRefundPresignRequest, presign))
sellerPresign, err := wire.UnmarshalPoolRefundPresignRequest(sellerPresignCBOR)
must(err)

presignResponse, err := sellerWorkflow.PresignPoolOpening(ctx, sellerPresign)
must(err)

_, buyerResponseCBOR := transmit(makePacket(wire.PoolRefundPresignResponse, presignResponse))
buyerResponse, err := wire.UnmarshalPoolRefundPresignResponse(buyerResponseCBOR)
must(err)

// This durably records the complete opening proof and initial payment state.
reference, err := buyerWorkflow.AcceptRefundPresign(
    ctx, presign, buyerResponse, fundingTx,
)
must(err)

fundingDelivery, err := buyerWorkflow.BuildFundingTxDelivery(fundingTx)
must(err)
_, fundingCBOR := transmit(makePacket(wire.PoolFundingTxDelivery, fundingDelivery))
sellerFunding, err := wire.UnmarshalPoolFundingTxDelivery(fundingCBOR)
must(err)

// Only now does the seller verify and submit the funding transaction.
_, err = sellerWorkflow.AcceptPoolFunding(ctx, sellerFunding)
must(err)
```

`PreparePoolOpening` and `PresignPoolOpening` use the pool-opening hooks. The underlying MultisigPool needs the actual private key to calculate transaction signatures, so this capability is normally wrapped in a `PrivateKeyProvider` inside the pool adapter. It is a different layer from the general-purpose credential `Signer`.

### 4. The buyer requests content and the seller delivers it

This example requests a block, so the buyer's `SeedSource` must provide the seed committed by the quote. For a seed request, use `ContentType: bitfs.ContentSeed` and no `SeedSource` is needed.

```go
contentHash := app.RequestedBlockHash()
request, err := buyerWorkflow.RequestContent(ctx, buyer.ContentRequestInput{
    QuoteTermsHash:        quoteHash,
    Pool:                  reference,
    SelectedArbiterPubKey: arbiterPubkey,
    Content: bitfs.ContentRef{
        Type: bitfs.ContentBlock,
        Hash: contentHash,
    },
    ContentSize:      app.ExpectedBlockSize(),
    DeliveryDeadline: bitfs.UnixSeconds(time.Now().Add(time.Hour).Unix()),
})
must(err)

_, requestCBOR := transmit(makePacket(wire.ContentRequest, request))
sellerRequest, err := wire.UnmarshalContentRequest(requestCBOR)
must(err)

// This verifies 003, acquires the seller-side latch, reads ContentSource,
// verifies the payload, and signs 004.
delivery, err := sellerWorkflow.DeliverRequestedContent(ctx, sellerRequest)
must(err)

_, deliveryCBOR := transmit(makePacket(wire.ContentDelivery, delivery))
buyerDelivery, err := wire.UnmarshalContentDelivery(deliveryCBOR)
must(err)
```

The buyer's `RequestContent` uses its own `Signer` to sign 003. The seller's `SignatureVerifier` checks it with the buyer public key committed by the quote. The seller then uses its own `Signer` to sign 004; the buyer verifies it with the seller public key from the quote.

### 5. The buyer accepts delivery and the seller accepts cumulative payment

```go
payment, err := buyerWorkflow.AcceptDelivery(ctx, request, buyerDelivery)
must(err)

_, paymentCBOR := transmit(makePacket(wire.CumulativePayment, payment))
sellerPayment, err := wire.UnmarshalPaymentUpdate(paymentCBOR)
must(err)

// The seller verifies the exact buyer signature, adds its own signature,
// submits the same cumulative state to the non-final pool, then persists it.
accepted, err := sellerWorkflow.AcceptPayment(ctx, sellerPayment)
must(err)
_ = accepted
```

There is no extra “payment succeeded” protocol message. The seller treats the node's acceptance of the same transaction as authoritative. An application may send a status notification, but that notification is not proof of pool or chain acceptance. Before constructing a negotiated close, the buyer must reconcile the node-accepted state into its own `buyerPools`.

### 6. Arbitration branch for a payment exception

This branch replaces `AcceptPayment`; it must not be executed alongside the normal payment path. The seller uses the already signed 003 authorization and its retained latest pool state to construct 007. The arbiter verifies the evidence and adds only its transaction signature.

```go
proof, err := sellerPools.LoadOpeningProof(ctx, reference.SpendTxID)
must(err)
latest, err := sellerPools.LoadAcceptedPayment(ctx, reference.SpendTxID)
must(err)

arbitrationRequest, err := sellerWorkflow.BuildArbitrationRequestFromAuthorization(
    ctx, proof, sellerRequest, latest,
)
must(err)

_, arbRequestCBOR := transmit(makePacket(wire.ArbitrationRequest, arbitrationRequest))
arbiterRequest, err := wire.UnmarshalArbitrationRequest(arbRequestCBOR)
must(err)

arbitrationResponse, err := arbiterWorkflow.SignPayment(ctx, arbiterRequest)
must(err)

_, arbResponseCBOR := transmit(makePacket(wire.ArbitrationResponse, arbitrationResponse))
arbiterResponse, err := wire.UnmarshalArbitrationResponse(arbResponseCBOR)
must(err)

arbitrated, err := sellerWorkflow.SubmitArbitratedPayment(
    ctx, arbiterRequest, arbiterResponse,
)
must(err)
_ = arbitrated
```

The arbiter's `AuthorizationVerifier` verifies the buyer signature in 003. The arbiter's own `Signer` only adds the arbiter signature after the candidate has passed all checks.

### 7. Two other endings: negotiated close and expiry refund

Negotiated close and expiry refund are alternative endings, not mandatory steps after normal payment. Negotiated close requires both parties' signatures and does not introduce a new CBOR `CloseRequest`. The example assumes that `buyerPools` has already been updated with the latest node-accepted state:

```go
opening, err := buyerPools.LoadOpeningProof(ctx, reference.SpendTxID)
must(err)
latestPayment, err := buyerPools.LoadAcceptedPayment(ctx, reference.SpendTxID)
must(err)

unsignedClose, buyerSig, err := buyerWorkflow.BuildImmediateClose(ctx, pool.CloseInput{
    Opening:              opening,
    Latest:               latestPayment,
    SellerAmountAfterSat: latestPayment.SellerAmountSat,
})
must(err)

closed, err := sellerWorkflow.SignImmediateClose(ctx, unsignedClose, buyerSig, sellerSigner)
must(err)

_, err = buyerWorkflow.SubmitImmediateClose(ctx, closed)
must(err)
```

If the pool has expired and no higher accepted payment state exists, the buyer can use the unilateral refund path:

```go
_, err = buyerWorkflow.RefundAfterExpiry(ctx, reference.SpendTxID)
must(err)
```

Throughout this example, the application owns dependencies and transport. The workflows own role ordering, exact CBOR, signature binding, state checks, and submission timing. Applications MUST NOT JSON-re-encode these objects or add transport fields that determine payment amounts or sequences.
