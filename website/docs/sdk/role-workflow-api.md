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
    Signer       Signer             // Buyer credential and transaction signing.
    Verifier     SignatureVerifier  // Seller quote and delivery verification.
    Clock        Clock              // Quote and delivery deadline checks.
    Quotes       QuoteStore         // Verified quotes indexed by QuoteTermsHash.
    Pools        PoolStore          // Opening proofs and accepted payment states.
    Transactions MultisigPoolPort    // Canonical MultisigPool operations.
    Node         NonFinalPoolNode    // Expiry-refund and negotiated-close submission.
    ContentSink  ContentSink         // Optional storage after 004 verification.
    SeedSource   SeedSource          // Verified seed for block requests; optional for seed requests.
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
    input buyer.ContentRequestInput,
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
func (workflow *buyer.Workflow) RefundAfterExpiry(ctx context.Context, spendTxID Hash32) (Hash32, error)

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
) (Hash32, error)
```

`ContentRequestInput` includes a verified quote, `SpendTxID`, expected current `BasePaymentSequence`, selected arbiter key, `ContentRef`, and delivery deadline. It does not accept a block index, quote price, or arbitrary seller amount.

## Seller API

The seller API encloses the risky “deliver first, receive payment later” window in one operation: validate 003, atomically acquire the latch, then load and sign 004. Callers MUST NOT bypass `DeliverRequestedContent` to deliver content directly.

```go
// package seller
type WorkflowConfig struct {
    Signer       Signer              // Seller quote, delivery, and transaction signing.
    Verifier     SignatureVerifier   // Buyer request verification.
    Clock        Clock               // Quote, request, and delivery deadline checks.
    Quotes       QuoteStore          // Seller quotes indexed by QuoteTermsHash.
    Pools        PoolStore           // Opening proofs and accepted payment states.
    Pending      PendingRequestStore // One-request latch with atomic TryAcquire.
    Content      ContentSource       // Raw content indexed by content hash.
    Transactions MultisigPoolPort     // Transaction checks and seller signatures.
    Node         NonFinalPoolNode     // Deferred transaction submission.
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
// then adds the seller signature and returns a complete transaction without
// broadcasting it.
func (workflow *seller.Workflow) SignImmediateClose(
    ctx context.Context,
    close *pool.UnsignedPayment,
    buyerSignature []byte,
    signer pool.Signer,
) (*pool.SignedPayment, error)

// BuildArbitrationRequest constructs an unsigned candidate from final 003
// authorization and the current state and adds the seller signature.
func (workflow *seller.Workflow) BuildArbitrationRequest(
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
    Signer Signer   // Arbiter transaction-signing capability.
    Pool   PoolPort // Payment-pool verification and arbiter signing.
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error)

// Client is an arbitration transport implemented by the seller application
// over HTTP, a queue, or a local call. Request and response are deterministic
// CBOR credentials defined by 007.
type Client interface {
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

## Minimal application call path

The application chooses its network. This pseudocode shows how role APIs connect; it does not require the SDK to provide HTTP or RPC:

```go
// Buyer creates 003 and sends it to the seller.
request, err := buyerWorkflow.RequestContent(ctx, requestInput)

// Seller atomically locks the pool, loads content, and returns 004.
delivery, err := sellerWorkflow.DeliverRequestedContent(ctx, request)

// Buyer accepts content and sends the resulting 005 to the seller.
payment, err := buyerWorkflow.AcceptDelivery(ctx, request, delivery)

// Seller verifies, completes, and submits the transaction. There is no extra
// application-level 005 acknowledgement.
accepted, err := sellerWorkflow.AcceptPayment(ctx, payment)
_ = accepted
```

Applications pass the `[]byte` returned by `wire.Marshal…` through any network adapter and call the matching `wire.Unmarshal…` on receipt. They MUST NOT sign a JSON re-encoding or add transport fields that determine payment amounts or sequences.
