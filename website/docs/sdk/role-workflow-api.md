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

// BuildArbitrationContentRequest rebuilds the Claim ID from the buyer's own
// opening plus the exact signed 003 through the shared Claim builder, signs
// [4, 10, claim_id, nonce] with the fixed message path, self-verifies, and
// returns a deep-copied Kind 10. The nonce is 32 application-generated random
// bytes; no quote/deadline/refund gate applies here (post-hoc recovery).
func (workflow *Workflow) BuildArbitrationContentRequest(ctx context.Context, opening *pool.OpeningProof, authorization *bitfs.SignedContentRequest, nonce []byte) (*arbitration.ContentRetrievalRequest, error)

// AcceptArbitratedContent verifies a Kind 11 response end to end without any
// clock read: time-independent quote/003/opening evidence, exact Kind 10 check,
// byte-for-byte embedded-vs-local ClaimCBOR comparison, full custody evidence
// chain (Seller Claim, Receipt Claim ID, receipt signature, transaction
// signature), payload membership/lengths/pricing and previous-state continuity.
type ArbitratedContentInput struct {
    Seed []byte // required when the retrieved batch includes any block
}

type VerifiedArbitratedContent struct {
    ClaimID  []byte                              // verified arbitration claim identity
    Payloads [][]byte                            // verified content in authorized order
    Receipt  *arbitration.ArbitrationReceipt     // Kind 9 audit data
}

// The result deliberately has no PaymentUpdate: 008 acceptance never produces
// a 005, never signs a buyer transaction, and never constructs a close.
func (workflow *Workflow) AcceptArbitratedContent(ctx context.Context, quote *bitfs.SignedFileQuote, opening *pool.OpeningProof, previous *pool.PaymentState, authorization *bitfs.SignedContentRequest, retrievalRequest *arbitration.ContentRetrievalRequest, retrievalResponse *arbitration.ContentRetrievalResponse, input ArbitratedContentInput) (*VerifiedArbitratedContent, error)
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

// BuildArbitrationRequest verifies the local opening, 003 authorization and
// 004 payload bundle, then signs only the Claim evidence. It does not build or
// sign a payment transaction.
func (workflow *Workflow) BuildArbitrationRequest(ctx context.Context, opening *pool.OpeningProof, authorization *bitfs.SignedContentRequest, delivery *bitfs.SignedContentDelivery, blockHeight uint32) (*arbitration.ArbitrationRequest, error)

// CompleteArbitratedPayment rebuilds the paid candidate from Kind 8 Claim
// evidence plus the Receipt's arbiter amount, verifies the Receipt message
// signature and the Arbiter transaction signature, then creates and merges the
// Seller transaction signature. Broadcasting is the application's job.
func (workflow *Workflow) CompleteArbitratedPayment(ctx context.Context, request *arbitration.ArbitrationRequest, response *arbitration.ArbitrationResponse, blockHeight uint32) (*pool.SignedPayment, error)
```

## Arbiter API

The arbiter receives complete evidence instead of querying buyer or seller state. It does not decide whether content was delivered or recalculate quote amounts. The arbitration fee is an application decision: price it from exactly `len(request.ContentPayloadsCBOR)` with your own integer policy, and hand the explicit amount to the SDK.

```go
// package arbitration
type WorkflowConfig struct {
    PrivateKey *ec.PrivateKey // official BSV Go SDK private key
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error)

// ArbitrationReceipt is the inner three-element Kind 9 document: Claim ID,
// positive arbiter amount, and the ForkID|All transaction signature over the
// independently rebuilt candidate.
type ArbitrationReceipt struct {
    ClaimID                     []byte
    ArbiterAmountSat            uint64
    ArbiterTransactionSignature []byte
}

// ArbitrationResponse is the exact four-element Kind 9 message.
type ArbitrationResponse struct {
    Version                 uint64
    ReceiptCBOR             []byte
    ArbiterReceiptSignature []byte
}

// ArbitrationClaimID returns SHA-256(deterministic-CBOR([4, 8, exact_claim_cbor])).
func ArbitrationClaimID(claimCBOR []byte) ([]byte, error)
func ValidateReceipt(receipt *ArbitrationReceipt) error
func MarshalReceipt(receipt *ArbitrationReceipt) ([]byte, error)
func UnmarshalReceipt(raw []byte) (*ArbitrationReceipt, error)
func ArbiterReceiptSigningCBOR(receiptCBOR []byte) ([]byte, error)

// PreparePayment validates Claim, Buyer authorization, Seller Claim signature,
// payload custody, and the independently rebuilt candidate for the caller's
// explicit positive fee (zero is rejected as invalid evidence; a fee that no
// longer fits returns pool.ErrInsufficientBalance). It creates no signature;
// the application persists exact evidence next.
func (workflow *arbitration.Workflow) PreparePayment(ctx context.Context, request *arbitration.ArbitrationRequest, blockHeight uint32, arbiterAmountSat uint64) (*arbitration.PreparedPayment, error)

// SignPreparedPayment rechecks the opaque prepared evidence against the frozen
// exact request and frozen fee, independently rebuilds the candidate, signs the
// transaction signature first, encodes the Receipt, and returns the response
// carrying both the receipt message signature over [4, 9, exact_receipt_cbor]
// and the transaction signature inside it.
func (workflow *arbitration.Workflow) SignPreparedPayment(ctx context.Context, prepared *arbitration.PreparedPayment) (*arbitration.ArbitrationResponse, error)

// PreparedPayment deep-copy getters: Request(), ContentPayloadsCBOR(),
// ContentPayloads(), ClaimID(), ArbiterAmountSat(), PaymentAuthorizationHash(),
// UnsignedPayment(), DeadlineUnix(), PreparedAt().

// ContentRetrievalRequest is the exact five-element Kind 10 message.
type ContentRetrievalRequest struct {
    Version        uint64
    ClaimID        []byte // 32 bytes
    Nonce          []byte // 32 bytes, not all zero
    BuyerSignature []byte
}

// ContentRetrievalResponse is the exact four-element Kind 11 message embedding
// the exact persisted Kind 8/9 bytes verbatim; payloads appear only once,
// inside the embedded Kind 8. No third outer signature exists on Kind 11.
type ContentRetrievalResponse struct {
    Version                 uint64
    ArbitrationRequestCBOR  []byte
    ArbitrationResponseCBOR []byte
}

// VerifiedCustodiedContent is the deep-copied result of full custody evidence
// verification: Claim ID, payload bundle, Receipt, and both embedded messages.
type VerifiedCustodiedContent struct {
    ClaimID      []byte
    PayloadsCBOR []byte
    Payloads     [][]byte
    Receipt      *ArbitrationReceipt
    Request      *ArbitrationRequest
    Response     *ArbitrationResponse
}

func BuyerRetrievalSigningCBOR(claimID, nonce []byte) ([]byte, error)
func MarshalContentRetrievalRequest(request *ContentRetrievalRequest) ([]byte, error)
func UnmarshalContentRetrievalRequest(raw []byte) (*ContentRetrievalRequest, error)
func ValidateContentRetrievalResponse(response *ContentRetrievalResponse) error
func MarshalContentRetrievalResponse(response *ContentRetrievalResponse) ([]byte, error)
func UnmarshalContentRetrievalResponse(raw []byte) (*ContentRetrievalResponse, error)

// VerifyCustodiedContent runs the complete time-independent evidence chain:
// strict decode of both children, Seller Claim signature, Buyer terms
// signature, payload count/order/hashes, Claim ID equality against the
// Receipt, receipt signature, and the transaction signature over the candidate
// rebuilt with the Receipt fee. It never reads a clock.
func VerifyCustodiedContent(arbitrationRequest *ArbitrationRequest, arbitrationResponse *ArbitrationResponse) (*VerifiedCustodiedContent, error)

// VerifyContentRetrievalRequest authenticates one Kind 10 against a stored
// record: full custody verification first, then the arbiter-key check, then
// the buyer signature over [4, 10, claim_id, nonce] with the buyer key
// recovered from the stored Claim. The application still owns lookup, nonce
// atomicity, retention, and transport.
func (workflow *Workflow) VerifyContentRetrievalRequest(retrievalRequest *ContentRetrievalRequest, storedArbitrationRequest *ArbitrationRequest, storedArbitrationResponse *ArbitrationResponse) (*VerifiedCustodiedContent, error)

// BuildContentRetrievalResponse wraps two exact persisted custody documents
// into Kind 11 after strict decoding and fully verifying them; the original
// bytes are embedded verbatim, never re-encoded.
func BuildContentRetrievalResponse(exactKind8, exactKind9 []byte) (*ContentRetrievalResponse, error)
```

The pool package also exposes one deliberately public pure function for the
007 evidence path:

```go
// package pool
// ValidateArbitrationClaimStructure performs the pure Claim-structure checks of
// the 007 candidate (source context, role scripts, canonical refund template
// with zero Seller/Arbiter initial amounts, sequence ordering, Seller balance)
// without depending on any arbitration fee. Evidence validation uses it so no
// placeholder amount is ever needed; the success builder additionally requires
// a positive fee. It is intentionally exported for cross-package reuse and has
// no signing or side effects.
func ValidateArbitrationClaimStructure(poolOutputSatoshis uint64, poolOutputLockingScript, refundTemplateRaw []byte, paymentSequence uint32, sellerAmountAfterSat uint64) error
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
delivery := journal.LoadExactContentDelivery(authorization)         // retained 004 payload bundle
arbitrationRequest, err := sellerWorkflow.BuildArbitrationRequest(ctx,
    opening, authorization, delivery, blockHeight)
// The application prices the fee from the exact payload CBOR length, then
// hands the explicit amount to the SDK.
arbiterAmountSat := arbiterFeePolicy(len(arbitrationRequest.ContentPayloadsCBOR))
prepared, err := arbiterWorkflow.PreparePayment(ctx, arbitrationRequest, blockHeight, arbiterAmountSat)
if err := journal.PersistArbitrationCustody(prepared); err != nil { /* ... */ }
response, err := arbiterWorkflow.SignPreparedPayment(ctx, prepared)
signed, err := sellerWorkflow.CompleteArbitratedPayment(ctx,
    arbitrationRequest, response, blockHeight)
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

### 8. Buyer retrieval of arbitrated custody content (008)

When the seller and buyer cannot connect directly but both reach the arbiter:

```go
// Buyer: rebuilds the Claim ID locally from opening + exact signed 003 only;
// the nonce comes from the application's crypto/rand source.
nonce := make([]byte, arbitration.RetrievalNonceBytes)
rand.Read(nonce)
retrievalRequest, err := buyerWorkflow.BuildArbitrationContentRequest(ctx,
    opening, sent003Authorization, nonce)
rawKind10, err := wire.MarshalArbitrationContentRequest(retrievalRequest)
journal.RecordOutbox("kind10", rawKind10) // persist BEFORE sending
sendToArbiter(rawKind10)

// Arbiter application: strict decode -> lookup -> Retrievable check ->
// VerifyContentRetrievalRequest (signature first) -> atomic nonce CAS ->
// BuildContentRetrievalResponse embedding the exact persisted Kind 8/9.
rawKind11 := handleContentRetrieval(rawKind10)
sendToBuyer(rawKind11)

// Buyer: full time-independent acceptance; no clock read anywhere.
kind11, err := wire.UnmarshalArbitrationContentResponse(rawKind11)
verified, err := buyerWorkflow.AcceptArbitratedContent(ctx, quote, opening,
    latest, sent003Authorization, retrievalRequest, kind11, buyer.ArbitratedContentInput{Seed: seedBytes})
for _, payload := range verified.Payloads { save(payload) } // app persistence
// verified has no PaymentUpdate: 008 never produces a 005 and never closes a
// pool. If the seller never submitted 007, the buyer waits or broadcasts its
// presigned RefundTx after nLockTime.
```

In every ending the SDK computes and verifies only; sending, broadcasting,
persisting, retrying, and reconciling are application actions.
