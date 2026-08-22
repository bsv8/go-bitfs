---
id: role-workflow-api
title: 03 · Role workflow API
---

# 03 · Role workflow API

Every workflow holds only the official BSV private key supplied at construction.
Methods never load or save state,
never send messages, never broadcast transactions, and never read a node; each
public entry reads system UTC once internally and takes the block height as an
explicit argument. Each method lists its wire input, local input, wire output,
local output, and side-effect guarantee. The application persists every returned local value
(keyed by `RefundTemplateTxID`), serializes concurrent work per pool, sends wire
messages, and broadcasts raw transactions through its own node adapter.

Recommended application ordering for every step:

```
load（按 RefundTemplateTxID） → SDK compute/verify → persist intent/result
→ send/broadcast → record outcome
```

## Buyer API

```go
// package buyer
type WorkflowConfig struct {
    PrivateKey *ec.PrivateKey // official BSV Go SDK private key
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error)

// BuyerOpeningState is buyer-private local state (wire: none; local: all).
type BuyerOpeningState struct {
    RefundTemplateTxID pool.RefundTemplateTxID
    Request      *pool.RefundPresignRequest
    FundingTx    []byte // never transmitted outside FundingTxDelivery
}

// PoolOpeningPreparation is the composite result of PreparePoolOpening.
type PoolOpeningPreparation struct {
    Request *pool.RefundPresignRequest // wire message to send to the seller
    State   *BuyerOpeningState         // local state to save BEFORE sending
}

// RefundPresignAcceptance is the composite result of AcceptRefundPresign.
type RefundPresignAcceptance struct {
    Reference      pool.Reference     // pool ID + current accepted sequence
    Opening        *pool.OpeningProof // complete proof incl. FundingTx (local)
    InitialPayment *pool.PaymentState // initial refund state (local)
}

// VerifiedDelivery is the composite result of AcceptDelivery.
type VerifiedDelivery struct {
    Payloads [][]byte            // verified payload batch, in 003 hash order (local, save them)
    Update   *pool.PaymentUpdate // minimal 005 credential: hash + buyer signature
}

// AcceptQuote verifies signature, terms, and expiry using system UTC read once
// at entry. Wire input: signed 001. Local output: accepted terms. No persistence.
func (workflow *Workflow) AcceptQuote(ctx context.Context, quote *bitfs.SignedFileQuote) (*bitfs.FileQuoteTerms, error)

// PreparePoolOpening builds and signs the generic 002 refund evidence.
// Wire input: none. Local input: pool.OpeningInput.
// Returns the wire request AND the private state that must be saved first.
func (workflow *Workflow) PreparePoolOpening(ctx context.Context, input pool.OpeningInput) (*PoolOpeningPreparation, error)

// AcceptRefundPresign verifies a 0202 response against the explicitly supplied
// saved opening state; re-derives RefundTemplateTxID and rejects any mismatch.
// Wire input: 0202 response. Local input: saved BuyerOpeningState.
func (workflow *Workflow) AcceptRefundPresign(ctx context.Context, state *BuyerOpeningState, response *pool.RefundPresignResponse) (*RefundPresignAcceptance, error)

// BuildFundingTxDelivery packages an already verified proof's funding
// transaction into the 0204 wire delivery. The caller passes the proof;
// nothing is loaded by hash.
func (workflow *Workflow) BuildFundingTxDelivery(ctx context.Context, opening *pool.OpeningProof) (*pool.FundingTxDelivery, error)

// BuildContentRequest verifies quote/opening/previous-state binding, price,
// and balance, then signs the 003 request with the workflow's private key.
// System UTC is read once at entry; the block height comes from the input.
// Reads no content.
func (workflow *Workflow) BuildContentRequest(ctx context.Context, quote *bitfs.SignedFileQuote, opening *pool.OpeningProof, previous *pool.PaymentState, input ContentRequestInput) (*bitfs.SignedContentRequest, error)

// AcceptDelivery verifies request linkage, seller signature, content hash and
// size, seed binding; returns verified payload plus the signed 005 update.
func (workflow *Workflow) AcceptDelivery(ctx context.Context, quote *bitfs.SignedFileQuote, opening *pool.OpeningProof, previous *pool.PaymentState, request *bitfs.SignedContentRequest, delivery *bitfs.SignedContentDelivery, input ContentDeliveryInput) (*VerifiedDelivery, error)

// BuildImmediateClose constructs the unsigned final close candidate and buyer
// detached signature from a caller-selected base state and caller-chosen
// target seller amount. The SDK does not claim base is the business-latest
// state. Send both values to the seller.
func (workflow *Workflow) BuildImmediateClose(ctx context.Context, opening *pool.OpeningProof, base *pool.PaymentState, targetSellerAmountSat uint64, blockHeight uint32) (*pool.UnsignedPayment, []byte, error)

// CompleteImmediateClose verifies only that the fully signed close is
// protocol-valid for the opening; whether it matches the business expectation
// and when to broadcast are the application's decisions.
func (workflow *Workflow) CompleteImmediateClose(ctx context.Context, opening *pool.OpeningProof, close *pool.SignedPayment) (*pool.SignedPayment, error)

// BuildRefundAfterExpiry verifies expiry from system UTC read once at entry
// plus the caller-provided height and merges the stored refund signatures into
// a broadcastable transaction. The SDK does not refuse construction because
// some local payment state exists. Broadcasting is the application's job.
func (workflow *Workflow) BuildRefundAfterExpiry(ctx context.Context, opening *pool.OpeningProof, blockHeight uint32) ([]byte, *pool.PaymentState, error)
```

Supporting input types:

```go
type ContentRequestInput struct {
    ContentHashes    [][]byte // ordered batch of 1..64 unique content hashes
    DeliveryDeadline bitfs.UnixSeconds
    Seed             []byte // required when the batch includes any block
    BlockHeight      uint32 // used only for height-locked refunds
}

type ContentDeliveryInput struct {
    Seed        []byte // required when accepting a batch that includes blocks
    BlockHeight uint32
}
```

## Seller API

The seller API has no lease or pending-request store: `BuildContentDelivery`
returns a lock-free `ContentDeliveryState` recording exactly the protocol
context needed later, and the application saves it and passes it back into
`AcceptPayment`.

```go
// package seller
type WorkflowConfig struct {
    PrivateKey *ec.PrivateKey // official BSV Go SDK private key
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error)

// SellerPresignResult is the composite result of PresignPoolOpening.
type SellerPresignResult struct {
    Response *pool.RefundPresignResponse // wire message back to the buyer
    Opening  *pool.OpeningProof          // local presign evidence; save FIRST
}

// PoolFundingAcceptance is the composite result of AcceptPoolFunding.
type PoolFundingAcceptance struct {
    Opening        *pool.OpeningProof // complete proof incl. FundingTx (local)
    InitialPayment *pool.PaymentState // initial refund state (local)
    FundingTx      []byte             // broadcast via YOUR node adapter
}

// ContentDeliveryState records the protocol context for validating the buyer's
// 005 credential for one delivery batch: the pool ID, authorization hash, target
// payment sequence, and absolute cumulative seller amount. It carries no
// owner/lease/acquire/held/release/expiry semantics — serialization is the
// caller's job.
type ContentDeliveryState struct {
    RefundTemplateTxID        pool.RefundTemplateTxID
    PaymentAuthorizationHash  pool.Hash32
    PaymentSequence           uint32
    SellerAmountAfterSat      uint64
}

// CreateQuote signs deterministic 001 terms using system UTC read once at
// entry. Saving the returned credential is the application's job.
func (workflow *Workflow) CreateQuote(ctx context.Context, draft bitfs.FileQuoteTerms, recommendedFilename string) (*bitfs.SignedFileQuote, error)

// PresignPoolOpening validates 0201 and returns the seller refund signature
// plus presign-form proof. Save Opening before sending Response.
func (workflow *Workflow) PresignPoolOpening(ctx context.Context, request *pool.RefundPresignRequest) (*SellerPresignResult, error)

// AcceptPoolFunding checks FundingTx against the explicitly supplied saved
// presign proof and computes the initial refund state. Nothing is submitted:
// broadcast the returned FundingTx yourself, then persist Opening and
// InitialPayment.
func (workflow *Workflow) AcceptPoolFunding(ctx context.Context, presignProof *pool.OpeningProof, delivery *pool.FundingTxDelivery) (*PoolFundingAcceptance, error)

// BuildContentDelivery verifies 003 against explicit quote/opening/previous
// state and caller-supplied content bytes, then signs 004. Save the returned
// ContentDeliveryState before sending the delivery.
func (workflow *Workflow) BuildContentDelivery(ctx context.Context, quote *bitfs.SignedFileQuote, opening *pool.OpeningProof, previous *pool.PaymentState, request *bitfs.SignedContentRequest, input ContentDeliveryInput) (*bitfs.SignedContentDelivery, *ContentDeliveryState, error)

// AcceptPayment verifies the minimal 005 credential (authorization hash plus
// buyer transaction signature) against the explicit original signed 003,
// opening proof, previous state, and saved ContentDeliveryState; rebuilds the
// unsigned state transaction locally through BuildPaymentUpdate; verifies the
// buyer signature over that exact rebuilt transaction; adds the seller
// signature and merges. Broadcast RawTx yourself.
func (workflow *Workflow) AcceptPayment(ctx context.Context, opening *pool.OpeningProof, previous *pool.PaymentState, authorization *bitfs.SignedContentRequest, deliveryState *ContentDeliveryState, update *pool.PaymentUpdate, blockHeight uint32) (*pool.SignedPayment, error)

// SignImmediateClose verifies the candidate structure and protocol amount
// boundaries against the opening and checks the buyer role signature with the
// fixed verifier, then adds the seller signature and merges without
// broadcasting. It does not judge whether the candidate matches any pending
// request or business-latest amount.
func (workflow *Workflow) SignImmediateClose(ctx context.Context, opening *pool.OpeningProof, unsigned *pool.UnsignedPayment, buyerSig []byte, blockHeight uint32) (*pool.SignedPayment, error)

// BuildArbitrationRequest verifies the retained signed 003 authorization and
// base state, constructs the authorized candidate, signs it, and packages
// the 007 evidence request. It never sends anything.
func (workflow *Workflow) BuildArbitrationRequest(ctx context.Context, opening *pool.OpeningProof, authorization *bitfs.SignedContentRequest, base *pool.PaymentState, blockHeight uint32) (*arbitration.ArbitrationRequest, error)

// CompleteArbitratedPayment verifies the 007 response hashes and arbiter
// signature against explicit evidence and merges seller+arbiter signatures.
// Broadcasting is the application's job.
func (workflow *Workflow) CompleteArbitratedPayment(ctx context.Context, opening *pool.OpeningProof, previous *pool.PaymentState, request *arbitration.ArbitrationRequest, response *arbitration.ArbitrationResponse, blockHeight uint32) (*pool.SignedPayment, error)
```

## Arbiter API

The arbiter receives complete evidence instead of querying buyer or seller state. It does not decide whether content was delivered or recalculate quote amounts.

```go
// package arbitration
type WorkflowConfig struct {
    PrivateKey *ec.PrivateKey // official BSV Go SDK private key
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

### 1. Create one capability set for each role

Each workflow needs exactly one official BSV private key; there is nothing else
to construct.

```go
buyerWorkflow, _ := buyer.NewWorkflow(buyer.WorkflowConfig{PrivateKey: buyerKey})
sellerWorkflow, _ := seller.NewWorkflow(seller.WorkflowConfig{PrivateKey: sellerKey})
arbiterWorkflow, _ := arbitration.NewWorkflow(arbitration.WorkflowConfig{PrivateKey: arbiterKey})
```

### 2. The seller creates a quote and the buyer accepts it

```go
quote, err := sellerWorkflow.CreateQuote(ctx, draftTerms, "file.bin")
save(quote) // seller-side persistence

terms, err := buyerWorkflow.AcceptQuote(ctx, quote)
```

### 3. The buyer and seller open the payment pool

```go
// 0201: compute request + private state; SAVE State BEFORE sending Request.
preparation, err := buyerWorkflow.PreparePoolOpening(ctx, pool.OpeningInput{ /* ... */ })
journal.SaveBuyerOpeningState(preparation.State)
send(preparation.Request)

// 0202: verify and presign; SAVE Opening BEFORE sending Response.
result, err := sellerWorkflow.PresignPoolOpening(ctx, receivedRequest)
journal.SaveSellerPresignProof(result.Opening)
send(result.Response)

// 0203: load the saved state by RefundTemplateTxID and pass it explicitly.
state := journal.LoadBuyerOpeningState(response.RefundTemplateTxID)
acceptance, err := buyerWorkflow.AcceptRefundPresign(ctx, state, response)
journal.SaveOpening("buyer", acceptance.Opening)
journal.SaveLatestPayment("buyer", acceptance.InitialPayment)

// 0204: package the verified proof's funding transaction.
delivery, err := buyerWorkflow.BuildFundingTxDelivery(ctx, acceptance.Opening)
send(delivery)

// 0205: verify funding against the saved presign proof.
opened, err := sellerWorkflow.AcceptPoolFunding(ctx, savedPresignProof, receivedDelivery)
journal.SaveOpening("seller", opened.Opening)
journal.SaveLatestPayment("seller", opened.InitialPayment)
broadcast(opened.FundingTx) // your node adapter declares acceptance
```

### 4. The buyer requests content and the seller delivers it

```go
request, err := buyerWorkflow.BuildContentRequest(ctx, quote, opening, latest, input)
journal.Record(request) // retain for 007

delivery, deliveryState, err := sellerWorkflow.BuildContentDelivery(ctx,
    quote, opening, latest, request,
    seller.ContentDeliveryInput{ContentPayloads: contentBatch, Seed: seedBytes})
journal.SaveDeliveryState(deliveryState) // save BEFORE sending
send(delivery)
```

### 5. The buyer accepts delivery and the seller accepts cumulative payment

```go
verified, err := buyerWorkflow.AcceptDelivery(ctx, quote, opening, latest, request,
    delivery, buyer.ContentDeliveryInput{Seed: seedBytes})
for _, payload := range verified.Payloads { save(payload) } // saving is the application's responsibility
// The minimal 005 credential carries only hash + buyer signature; index the
// exact original 003 under the authorization hash before sending it.
journal.IndexAuthorization(verified.Update.PaymentAuthorizationHash, request)
send(verified.Update)

authorization := journal.LoadAuthorizationByHash(verified.Update.PaymentAuthorizationHash)
signed, err := sellerWorkflow.AcceptPayment(ctx, opening, latest,
    authorization, savedDeliveryState, verified.Update, blockHeight)
journal.SaveLatestPayment("seller", &signed.State)
broadcast(signed.RawTx)
```

### 6. Arbitration branch for a payment exception

```go
authorization := journal.LoadSentContentRequest(refundTemplateTxID) // retained 003 bytes
arbitrationRequest, err := sellerWorkflow.BuildArbitrationRequest(ctx,
    opening, authorization, latest, blockHeight)
response := arbiter.SignPayment(arbitrationRequest)
signed, err := sellerWorkflow.CompleteArbitratedPayment(ctx,
    opening, latest, arbitrationRequest, response, blockHeight)
journal.SaveLatestPayment("seller", &signed.State)
broadcast(signed.RawTx)
```

### 7. Two other endings: negotiated close and expiry refund

```go
unsigned, buyerSig, _ := buyerWorkflow.BuildImmediateClose(ctx, opening, latest, targetSellerAmountSat, blockHeight)
closed, _ := sellerWorkflow.SignImmediateClose(ctx, opening, unsigned, buyerSig, blockHeight)
final, _ := buyerWorkflow.CompleteImmediateClose(ctx, opening, closed)
broadcast(final.RawTx)

raw, state, _ := buyerWorkflow.BuildRefundAfterExpiry(ctx, opening, currentHeight)
broadcast(raw)
```

In every ending the SDK computes and verifies only; sending, broadcasting,
persisting, retrying, and reconciling are application actions.
