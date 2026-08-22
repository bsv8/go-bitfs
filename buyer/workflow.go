package buyer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/internal/refundlock"
	"github.com/bsv8/go-bitfs/pool"
)

// WorkflowConfig supplies the buyer official BSV private key. It intentionally
// has no store, content, backend, node, clock, signer, or verifier fields:
// those concerns belong to the calling application, and signing always uses
// this key through the SDK's fixed implementations.
type WorkflowConfig struct {
	// PrivateKey is the caller-parsed official BSV Go SDK private key. It
	// never enters any wire message, local result, log, or persisted structure.
	PrivateKey *ec.PrivateKey
}

// Workflow is the stateless buyer protocol orchestrator for 001–006. It
// validates seller credentials and pool evidence, signs requests and payment
// updates with its derived key material, and computes the next wire message or
// local role state from explicit inputs only. Apart from the private key and
// the compressed public key derived from it, it holds no session state.
type Workflow struct {
	privateKey *ec.PrivateKey
	publicKey  []byte
}

// BuyerOpeningState is the buyer-private local state returned by
// PreparePoolOpening. The application must save it before sending Request to
// the seller; AcceptRefundPresign requires it again as an explicit argument.
// FundingTx stays private to the buyer until delivery in 0204 and must never
// be embedded in any network message other than FundingTxDelivery.
type BuyerOpeningState struct {
	// RefundTemplateTxID is the canonical pool correlation ID derived from Request.
	RefundTemplateTxID pool.RefundTemplateTxID
	// Request is the exact signed 0201 request produced for RefundTemplateTxID.
	Request *pool.RefundPresignRequest
	// FundingTx is the buyer's private funding transaction raw bytes.
	FundingTx []byte
}

// PoolOpeningPreparation is the composite result of PreparePoolOpening:
// Request is the wire message to send to the seller, and State is the local
// buyer state that the application must persist before sending it.
type PoolOpeningPreparation struct {
	// Request is the signed 0201 refund-presign request (wire message).
	Request *pool.RefundPresignRequest
	// State is the buyer-local opening state to persist (never transmitted).
	State *BuyerOpeningState
}

// RefundPresignAcceptance is the composite result of AcceptRefundPresign.
type RefundPresignAcceptance struct {
	// Reference identifies the opened pool and its base payment sequence.
	Reference pool.Reference
	// Opening is the complete, verified opening proof including FundingTx.
	Opening *pool.OpeningProof
	// InitialPayment is the initial refund payment state parsed from the
	// merged refund transaction.
	InitialPayment *pool.PaymentState
}

// NewWorkflow validates the buyer private key and returns a stateless workflow.
func NewWorkflow(config WorkflowConfig) (*Workflow, error) {
	if config.PrivateKey == nil {
		return nil, errors.New("buyer workflow requires a private key")
	}
	return &Workflow{privateKey: config.PrivateKey, publicKey: config.PrivateKey.PubKey().Compressed()}, nil
}

func (workflow *Workflow) engineFor(proof *pool.OpeningProof) (*pool.MultisigPoolEngine, error) {
	if proof == nil {
		return nil, fmt.Errorf("%w: opening proof is required", pool.ErrInvalidEvidence)
	}
	return pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey})
}

// verifyOpeningOwnership binds caller-supplied opening evidence to the
// compressed public key derived from this workflow's private key. Loading
// evidence by RefundTemplateTxID never authorizes another buyer's opening, so
// every method re-checks this binding; callers cannot supply a conflicting
// self-claimed public key.
func (workflow *Workflow) verifyOpeningOwnership(_ context.Context, proof *pool.OpeningProof) error {
	if workflow == nil || workflow.privateKey == nil {
		return fmt.Errorf("%w: buyer private key is required", pool.ErrInvalidEvidence)
	}
	if proof == nil {
		return fmt.Errorf("%w: opening proof is required", pool.ErrInvalidEvidence)
	}
	if !bytes.Equal(workflow.publicKey, proof.BuyerPubKey) {
		return fmt.Errorf("%w: workflow key does not match opening buyer", pool.ErrInvalidEvidence)
	}
	return nil
}

// checkPoolNotExpired 用调用方基准事实判断退款是否仍不可执行：时间戳锁定
// 与本操作唯一一次读取的 at 比较，高度锁定与调用方传入的 blockHeight 比较。
// 它是纯本地比较，不再触发任何内部读钟。
func checkPoolNotExpired(opening *pool.OpeningProof, at time.Time, blockHeight uint32) error {
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return err
	}
	if err := refundlock.CheckNotExpired(details.RefundLockTime, at, blockHeight); err != nil {
		return fmt.Errorf("%w: %s", pool.ErrInvalidEvidence, err)
	}
	return nil
}

// AcceptQuote verifies the seller signature, terms, and expiry using system
// UTC read once at entry, and returns the accepted terms. The application
// decides where to keep the quote; the SDK does not save anything.
func (workflow *Workflow) AcceptQuote(_ context.Context, quote *bitfs.SignedFileQuote) (*bitfs.FileQuoteTerms, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	localQuote := bitfs.CloneSignedFileQuote(quote)
	return bitfs.VerifySignedFileQuote(localQuote)
}

// PreparePoolOpening builds and signs the generic 002 refund evidence and
// returns both the wire request and the buyer-local state that must be saved
// before Request leaves this process. The private FundingTx lives only in the
// returned State; the SDK does not persist it anywhere.
func (workflow *Workflow) PreparePoolOpening(ctx context.Context, input pool.OpeningInput) (*PoolOpeningPreparation, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: workflow.publicKey, SellerPubKey: input.SellerPubKey, ArbiterPubKey: input.ArbiterPubKey})
	if err != nil {
		return nil, err
	}
	request, err := pool.NewBuyerPoolAdapter(engine, workflow.privateKey).BuildRefundPresignRequest(nil, pool.CloneOpeningInput(input))
	if err != nil {
		return nil, err
	}
	refundTemplateTxID, err := pool.DeriveRefundTemplateTxIDFromRequest(request)
	if err != nil {
		return nil, err
	}
	state := &BuyerOpeningState{RefundTemplateTxID: refundTemplateTxID, Request: pool.CloneRefundPresignRequest(request), FundingTx: append([]byte(nil), input.FundingTx...)}
	return &PoolOpeningPreparation{Request: request, State: state}, nil
}

// AcceptRefundPresign verifies a 0202 response against the explicitly
// supplied buyer-local opening state saved at 0201 time. It re-derives the
// RefundTemplateTxID from the stored request, rejects any mismatch between the
// local state and the response, verifies the seller signature against that
// exact request, and computes the complete OpeningProof plus initial payment
// state. Nothing is loaded from or written to any store: the application
// persists Opening and InitialPayment itself before sending anything further.
func (workflow *Workflow) AcceptRefundPresign(ctx context.Context, state *BuyerOpeningState, response *pool.RefundPresignResponse) (*RefundPresignAcceptance, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	localResponse := pool.CloneRefundPresignResponse(response)
	if err := pool.ValidateRefundPresignResponse(localResponse); err != nil {
		return nil, err
	}
	if state == nil || state.Request == nil {
		return nil, fmt.Errorf("%w: buyer opening state with its request is required", pool.ErrInvalidEvidence)
	}
	localRequest := pool.CloneRefundPresignRequest(state.Request)
	computed, err := pool.DeriveRefundTemplateTxIDFromRequest(localRequest)
	if err != nil {
		return nil, err
	}
	if computed != state.RefundTemplateTxID {
		return nil, fmt.Errorf("%w: buyer opening state does not match its request", pool.ErrInvalidEvidence)
	}
	if computed != localResponse.RefundTemplateTxID {
		return nil, fmt.Errorf("%w: refund presign response does not match stored request", pool.ErrInvalidEvidence)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: localRequest.BuyerPubKey, SellerPubKey: localRequest.SellerPubKey, ArbiterPubKey: localRequest.ArbiterPubKey})
	if err != nil {
		return nil, err
	}
	proof, err := engine.BuildOpeningProof(ctx, localRequest, localResponse.SellerRefundSignature, state.FundingTx)
	if err != nil {
		return nil, fmt.Errorf("build canonical opening proof: %w", err)
	}
	if err := workflow.verifyOpeningOwnership(ctx, proof); err != nil {
		return nil, err
	}
	initialRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		return nil, fmt.Errorf("assemble initial refund state: %w", err)
	}
	initial, err := engine.ParsePaymentState(ctx, initialRaw, proof)
	if err != nil {
		return nil, fmt.Errorf("parse initial pool state: %w", err)
	}
	if initial.PaymentSequence != 2 || initial.SellerAmountSat != 0 || initial.ArbiterAmountSat != 0 {
		return nil, fmt.Errorf("%w: refund transaction is not the initial pool state", pool.ErrInvalidEvidence)
	}
	return &RefundPresignAcceptance{
		Reference:      pool.Reference{RefundTemplateTxID: initial.RefundTemplateTxID, PaymentSequence: initial.PaymentSequence},
		Opening:        proof,
		InitialPayment: initial,
	}, nil
}

// BuildFundingTxDelivery packages the funding transaction carried by an
// already verified OpeningProof into the 0204 wire delivery container. The
// caller passes the proof explicitly; nothing is loaded by hash.
func (workflow *Workflow) BuildFundingTxDelivery(ctx context.Context, opening *pool.OpeningProof) (*pool.FundingTxDelivery, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	opening = pool.CloneOpeningProof(opening)
	if opening == nil {
		return nil, fmt.Errorf("%w: opening proof is missing", pool.ErrInvalidEvidence)
	}
	if err := workflow.verifyOpeningOwnership(ctx, opening); err != nil {
		return nil, err
	}
	refundTemplateTxID, err := pool.DeriveRefundTemplateTxID(ctx, opening)
	if err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("%w: opening proof is invalid: %v", pool.ErrInvalidEvidence, err)
	}
	if len(opening.FundingTx) == 0 {
		return nil, fmt.Errorf("%w: complete funding transaction is required", pool.ErrInvalidEvidence)
	}
	delivery := &pool.FundingTxDelivery{Version: pool.MajorVersion, RefundTemplateTxID: refundTemplateTxID, FundingTx: append([]byte(nil), opening.FundingTx...)}
	if err := pool.ValidateFundingTxDelivery(delivery); err != nil {
		return nil, err
	}
	return delivery, nil
}

// ContentRequestInput carries the ordered content batch and deadline facts
// for a 003 request. Quote, opening proof, previous payment state, time, and
// block height are explicit method parameters.
type ContentRequestInput struct {
	// ContentHashes is the ordered batch of content hashes to purchase in one
	// authorization. A hash equal to the quote SeedHash buys the seed; every
	// other hash must be committed by that seed. Duplicates are rejected.
	ContentHashes [][]byte
	// DeliveryDeadline is the UTC delivery deadline carried by the 003 terms.
	DeliveryDeadline bitfs.UnixSeconds
	// Seed contains the raw verified seed bytes whenever the batch includes
	// any block; it may be empty for a pure-seed batch.
	Seed []byte
	// BlockHeight is the caller-provided current block height, read only when
	// the opening's refund uses a block-height locktime.
	BlockHeight uint32
}

// BuildContentRequest verifies the quote, opening ownership, previous payment
// state, batch membership context, aggregate price, and balance, then signs
// the 003 request with this workflow's private key. System UTC is read once at
// entry; the block height arrives from the caller. It reads no content and
// changes no pool state; whether the supplied state is the business-latest one
// is the caller's call. Content kinds are derived exclusively from evidence:
// hashes equal to the quote SeedHash are seeds, all others must be committed
// by the verified seed and are priced at their protocol expected lengths with
// checked addition before any signature exists.
func (workflow *Workflow) BuildContentRequest(ctx context.Context, quote *bitfs.SignedFileQuote, opening *pool.OpeningProof, previous *pool.PaymentState, input ContentRequestInput) (*bitfs.SignedContentRequest, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	localQuote := bitfs.CloneSignedFileQuote(quote)
	opening = pool.CloneOpeningProof(opening)
	previous = pool.ClonePaymentState(previous)
	at := time.Now().UTC()
	openingDetails, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, fmt.Errorf("derive pool opening details: %w", err)
	}
	refundTemplateTxID := openingDetails.RefundTemplateTxID
	if err := workflow.verifyOpeningOwnership(ctx, opening); err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, fmt.Errorf("build pool engine: %w", err)
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	if err := checkPoolNotExpired(opening, at, input.BlockHeight); err != nil {
		return nil, errors.Join(bitfs.ErrInvalidEvidence, fmt.Errorf("verify pool refund is still available: %w", err))
	}
	// 时间无关证据验证；过期判断使用本操作唯一一次读取的 at。
	terms, err := bitfs.VerifyFileQuoteEvidence(localQuote)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(workflow.publicKey, terms.BuyerPubkey) {
		return nil, fmt.Errorf("%w: signer does not match quote buyer", bitfs.ErrInvalidEvidence)
	}
	if input.DeliveryDeadline <= bitfs.UnixSeconds(at.Unix()) {
		return nil, fmt.Errorf("%w: delivery deadline is not in the future", bitfs.ErrDeliveryDeadline)
	}
	// 本操作唯一一次读取的 at 同时用于报价过期与"截止不超过报价"判断，
	// 避免签出必然被卖方拒绝的过期授权。
	if !at.Before(time.Unix(terms.QuoteExpiresAtUnix, 0)) {
		return nil, fmt.Errorf("%w: file quote is expired", bitfs.ErrQuoteExpired)
	}
	if int64(input.DeliveryDeadline) > terms.QuoteExpiresAtUnix {
		return nil, fmt.Errorf("%w: delivery deadline exceeds quote expiry", bitfs.ErrDeliveryDeadline)
	}
	if !bytes.Equal(opening.BuyerPubKey, terms.BuyerPubkey) || !bytes.Equal(opening.SellerPubKey, localQuote.SellerPubkey) {
		return nil, fmt.Errorf("%w: verify pool participants", bitfs.ErrInvalidEvidence)
	}
	if !quoteAllowsArbiter(terms, opening.ArbiterPubKey) {
		return nil, fmt.Errorf("%w: opening arbiter is not allowed by quote", bitfs.ErrInvalidEvidence)
	}
	if previous == nil || previous.RefundTemplateTxID != refundTemplateTxID || previous.PaymentSequence+1 == 0 {
		return nil, bitfs.ErrStalePaymentSequence
	}
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	targetSequence := previous.PaymentSequence + 1
	if previous.PaymentSequence >= ^uint32(0)-1 {
		return nil, bitfs.ErrStalePaymentSequence
	}
	contentHashes := make([][]byte, len(input.ContentHashes))
	for index, hash := range input.ContentHashes {
		contentHashes[index] = append([]byte(nil), hash...)
	}
	contentHashesCBOR, err := bitfs.EncodeContentHashes(contentHashes)
	if err != nil {
		return nil, err
	}
	seed := append([]byte(nil), input.Seed...)
	// 批量分类与定价：块成员资格、期望长度和逐项 checked-add 都在签名前完成。
	price, err := bitfs.ContentHashesPriceSat(terms, contentHashes, seed)
	if err != nil {
		return nil, err
	}
	if previous.SellerAmountSat > ^uint64(0)-price {
		return nil, bitfs.ErrInsufficientBalance
	}
	sellerAmountAfter := previous.SellerAmountSat + price
	if err := engine.CheckPaymentCapacity(ctx, pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequence: targetSequence, SellerAmountAfterSat: sellerAmountAfter}); err != nil {
		return nil, err
	}
	quoteHash, err := bitfs.FileQuoteTermsHash(localQuote.TermsCBOR)
	if err != nil {
		return nil, err
	}
	requestTerms := &bitfs.ContentRequestTerms{
		QuoteTermsHash:       quoteHash[:],
		RefundTemplateTxID:   refundTemplateTxID[:],
		PaymentSequence:      targetSequence,
		SellerAmountAfterSat: sellerAmountAfter,
		ContentHashesCBOR:    contentHashesCBOR,
		DeliveryDeadlineUnix: int64(input.DeliveryDeadline),
	}
	return bitfs.NewSignedContentRequest(requestTerms, workflow.privateKey)
}

// VerifiedDelivery is the composite result of AcceptDelivery: Payloads holds
// the verified content batch in authorized order for the application to
// persist, and Update is the single signed 005 wire update for the whole batch.
type VerifiedDelivery struct {
	// Payloads contains the verified payload bytes, ordered exactly like the
	// hashes committed in the referenced 003.
	Payloads [][]byte
	// Update is the signed cumulative payment update (wire message).
	Update *pool.PaymentUpdate
}

// ContentDeliveryInput carries the caller-provided verification inputs for a
// 004 delivery beyond the wire messages themselves.
type ContentDeliveryInput struct {
	// Seed contains the raw seed bytes when the delivered batch includes any
	// block; it may be empty when a pure-seed batch itself carries the seed.
	Seed []byte
	// BlockHeight is the caller-provided current block height, read only when
	// the opening's refund uses a block-height locktime.
	BlockHeight uint32
}

// AcceptDelivery verifies one complete 004 delivery against the exact original
// 003 the application routed by PaymentAuthorizationHash. Before any payload
// or payment work it re-validates the full time-independent 003 evidence:
// quote signature, buyer signature over the exact TermsCBOR, QuoteTermsHash
// match, and Buyer/Seller/Arbiter binding to the explicitly supplied
// OpeningProof — a delivery whose authorization was never signed by this
// buyer can never reach 005 here. It then re-computes and compares the
// authorization hash, verifies the seller signature over the bare 32-byte
// hash, and validates every payload's count, order, hash, membership, and
// protocol length before recomputing the aggregate price, target sequence,
// and absolute cumulative amount. Only when all items succeed does it build
// and sign exactly one 005. System UTC is read once at entry; saving the
// returned payloads is the application's job.
func (workflow *Workflow) AcceptDelivery(ctx context.Context, quote *bitfs.SignedFileQuote, opening *pool.OpeningProof, previous *pool.PaymentState, request *bitfs.SignedContentRequest, delivery *bitfs.SignedContentDelivery, input ContentDeliveryInput) (*VerifiedDelivery, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	localRequest := bitfs.CloneSignedContentRequest(request)
	localDelivery := bitfs.CloneSignedContentDelivery(delivery)
	if localRequest == nil || localDelivery == nil {
		return nil, fmt.Errorf("%w: content request and delivery are required", bitfs.ErrInvalidEvidence)
	}
	opening = pool.CloneOpeningProof(opening)
	previous = pool.ClonePaymentState(previous)
	at := time.Now().UTC()
	localQuote := bitfs.CloneSignedFileQuote(quote)
	if err := workflow.verifyOpeningOwnership(ctx, opening); err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	if err := checkPoolNotExpired(opening, at, input.BlockHeight); err != nil {
		return nil, fmt.Errorf("verify pool refund is still available: %w", err)
	}
	// 完整时间无关证据验证：报价签名、池绑定、买方签名、报价哈希与角色绑定。
	// 未获本买方签名的伪造 003 在此被拒绝，绝不进入 payload 校验或 005 构造。
	requestTerms, quoteTerms, err := bitfs.VerifyContentRequestEvidence(localRequest, localQuote, opening)
	if err != nil {
		return nil, err
	}
	refundTemplateTxID := pool.RefundTemplateTxID(bytes.Clone(requestTerms.RefundTemplateTxID))
	openingDetails, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, fmt.Errorf("derive pool opening details: %w", err)
	}
	if openingDetails.RefundTemplateTxID != refundTemplateTxID {
		return nil, fmt.Errorf("%w: content request is not bound to opening proof", bitfs.ErrInvalidEvidence)
	}
	// 本操作唯一一次读取的 at 同时用于报价过期与交付截止判断。
	if err := checkRequestTimingLocal(requestTerms, quoteTerms, at); err != nil {
		return nil, err
	}
	// 重新计算 003 授权哈希并逐字节比较；004 只携带这个 32 字节哈希。
	requestHash, err := bitfs.PaymentAuthorizationHash(localRequest.TermsCBOR)
	if err != nil {
		return nil, err
	}
	if len(localDelivery.PaymentAuthorizationHash) != sha256.Size || !bytes.Equal(localDelivery.PaymentAuthorizationHash, requestHash[:]) {
		return nil, fmt.Errorf("%w: delivery does not reference supplied request", bitfs.ErrInvalidEvidence)
	}
	// 卖方签名只覆盖精确 32 字节授权哈希（裸消息签名路径）。
	if err := bitfs.VerifySignature(opening.SellerPubKey, localDelivery.PaymentAuthorizationHash, localDelivery.SellerPaymentAuthorizationHashSignature); err != nil {
		return nil, fmt.Errorf("%w: seller signature invalid: %v", bitfs.ErrInvalidEvidence, err)
	}
	contentHashes, err := bitfs.DecodeContentHashes(requestTerms.ContentHashesCBOR)
	if err != nil {
		return nil, err
	}
	payloads, err := bitfs.DecodeContentPayloads(localDelivery.ContentPayloadsCBOR)
	if err != nil {
		return nil, err
	}
	seed := append([]byte(nil), input.Seed...)
	effectiveSeed, err := bitfs.VerifyContentPayloadsContext(ctx, quoteTerms, contentHashes, payloads, seed)
	if err != nil {
		return nil, err
	}
	if previous == nil || previous.RefundTemplateTxID != refundTemplateTxID || previous.PaymentSequence+1 != requestTerms.PaymentSequence {
		return nil, bitfs.ErrStalePaymentSequence
	}
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	if previous.PaymentSequence >= ^uint32(0)-1 {
		return nil, fmt.Errorf("%w: payment sequence exhausted", bitfs.ErrStalePaymentSequence)
	}
	price, err := bitfs.ContentHashesPriceSat(quoteTerms, contentHashes, effectiveSeed)
	if err != nil {
		return nil, err
	}
	if previous.SellerAmountSat > ^uint64(0)-price || requestTerms.SellerAmountAfterSat != previous.SellerAmountSat+price {
		return nil, fmt.Errorf("%w: seller amount does not match aggregate content price", bitfs.ErrInvalidEvidence)
	}
	updateInput := pool.PaymentUpdateInput{
		Opening:              opening,
		Previous:             previous,
		PaymentSequence:      requestTerms.PaymentSequence,
		SellerAmountAfterSat: requestTerms.SellerAmountAfterSat,
	}
	if err := engine.CheckPaymentCapacity(ctx, updateInput); err != nil {
		return nil, err
	}
	unsigned, err := engine.BuildPaymentUpdate(ctx, updateInput)
	if err != nil {
		return nil, fmt.Errorf("build payment update: %w", err)
	}
	buyerSig, err := pool.NewBuyerPoolAdapter(engine, workflow.privateKey).SignBuyerPayment(ctx, unsigned, opening)
	if err != nil {
		return nil, fmt.Errorf("sign payment update: %w", err)
	}
	if err := engine.VerifyBuyerPayment(unsigned, buyerSig, opening); err != nil {
		return nil, fmt.Errorf("verify buyer payment: %w", err)
	}
	if unsigned == nil || unsigned.RefundTemplateTxID != refundTemplateTxID || unsigned.PaymentSequence <= previous.PaymentSequence {
		return nil, fmt.Errorf("%w: signed payment state is stale", bitfs.ErrStalePaymentSequence)
	}
	update := &pool.PaymentUpdate{
		Version:                   pool.MajorVersion,
		RefundTemplateTxID:        refundTemplateTxID,
		PaymentAuthorizationHash:  append([]byte(nil), requestHash[:]...),
		UnsignedStateTxRaw:        append([]byte(nil), unsigned.RawTx...),
		BuyerTransactionSignature: append([]byte(nil), buyerSig...),
	}
	verifiedPayloads := make([][]byte, len(payloads))
	for index := range payloads {
		verifiedPayloads[index] = append([]byte(nil), payloads[index]...)
	}
	return &VerifiedDelivery{Payloads: verifiedPayloads, Update: update}, nil
}

// BuildImmediateClose constructs the unsigned immediate-close candidate and
// the buyer detached signature from a caller-selected base state and a caller
// chosen target seller amount. The SDK does not claim base is the business
// latest state and does not judge whether targetAmount matches any order or
// ledger; it only enforces protocol encoding and capacity boundaries. The
// timestamp lock uses system UTC read once at entry and the height lock uses
// the caller-provided block height. The application sends both values to the
// seller, who adds its signature via SignImmediateClose.
func (workflow *Workflow) BuildImmediateClose(ctx context.Context, opening *pool.OpeningProof, base *pool.PaymentState, targetSellerAmountSat uint64, blockHeight uint32) (*pool.UnsignedPayment, []byte, error) {
	if workflow == nil {
		return nil, nil, errors.New("buyer workflow is required")
	}
	opening = pool.CloneOpeningProof(opening)
	base = pool.ClonePaymentState(base)
	if err := workflow.verifyOpeningOwnership(ctx, opening); err != nil {
		return nil, nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, nil, err
	}
	if err := checkPoolNotExpired(opening, time.Now().UTC(), blockHeight); err != nil {
		return nil, nil, err
	}
	if base == nil {
		return nil, nil, fmt.Errorf("%w: base payment state is required", pool.ErrInvalidEvidence)
	}
	unsigned, err := engine.BuildImmediateClose(ctx, pool.CloseInput{Opening: opening, Base: base, SellerAmountAfterSat: targetSellerAmountSat})
	if err != nil {
		return nil, nil, err
	}
	buyerSig, err := pool.NewBuyerPoolAdapter(engine, workflow.privateKey).SignBuyerPayment(ctx, unsigned, opening)
	if err != nil {
		return nil, nil, err
	}
	if unsigned == nil || unsigned.PaymentSequence != ^uint32(0) {
		return nil, nil, fmt.Errorf("%w: immediate close is not final", pool.ErrInvalidEvidence)
	}
	if err := engine.VerifyBuyerPayment(unsigned, buyerSig, opening); err != nil {
		return nil, nil, fmt.Errorf("verify immediate close: %w", err)
	}
	return unsigned, buyerSig, nil
}

// CompleteImmediateClose verifies that a fully signed final close computed by
// the seller is cryptographically, structurally, and transactionally valid for
// the given opening, and returns it as a complete SignedPayment. It does not
// claim the result corresponds to the caller's pending request, is based on
// the database-latest state, or should be broadcast; those are business
// decisions. Applications needing strict request matching can persist their
// own request ID plus unsigned candidate and compare with pure helpers.
func (workflow *Workflow) CompleteImmediateClose(ctx context.Context, opening *pool.OpeningProof, close *pool.SignedPayment) (*pool.SignedPayment, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	localClose := pool.CloneSignedPayment(close)
	if localClose == nil || localClose.State.PaymentSequence != ^uint32(0) || len(localClose.RawTx) == 0 || !bytes.Equal(localClose.State.RawTx, localClose.RawTx) {
		return nil, fmt.Errorf("%w: final signed payment is required", pool.ErrInvalidEvidence)
	}
	opening = pool.CloneOpeningProof(opening)
	if err := workflow.verifyOpeningOwnership(ctx, opening); err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyCompletedFinalPayment(localClose, opening); err != nil {
		return nil, fmt.Errorf("verify final payment: %w", err)
	}
	return localClose, nil
}

// BuildRefundAfterExpiry verifies that the refund locktime has been reached —
// reading system UTC once for timestamp locks and using the caller-provided
// block height for height locks — merges the opening signatures into a
// broadcastable refund transaction, and returns its raw bytes together with
// the parsed initial payment state. The SDK does not refuse construction
// because some local payment state exists, does not judge business conflicts,
// and never submits or marks uncertain outcomes; broadcasting is the
// application's decision.
func (workflow *Workflow) BuildRefundAfterExpiry(ctx context.Context, opening *pool.OpeningProof, blockHeight uint32) ([]byte, *pool.PaymentState, error) {
	if workflow == nil {
		return nil, nil, errors.New("buyer workflow is required")
	}
	opening = pool.CloneOpeningProof(opening)
	if err := workflow.verifyOpeningOwnership(ctx, opening); err != nil {
		return nil, nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, nil, err
	}
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, nil, err
	}
	if err := refundlock.CheckExpired(details.RefundLockTime, time.Now().UTC(), blockHeight); err != nil {
		return nil, nil, err
	}
	raw, err := engine.BuildRefundSubmission(opening)
	if err != nil {
		return nil, nil, err
	}
	txID, err := engine.TransactionID(opening.RefundTx)
	if err != nil {
		return nil, nil, err
	}
	state, err := engine.ParsePaymentState(ctx, raw, opening)
	if err != nil {
		return nil, nil, fmt.Errorf("parse refund payment state: %w", err)
	}
	if state.RefundTemplateTxID != (pool.RefundTemplateTxID(txID)) {
		return nil, nil, fmt.Errorf("%w: refund transaction does not match opening correlation ID", pool.ErrInvalidEvidence)
	}
	return raw, state, nil
}

func quoteAllowsArbiter(terms *bitfs.FileQuoteTerms, wanted []byte) bool {
	pubkeys, err := bitfs.DecodeSupportedArbiterPubkeys(terms.SupportedArbiterPubkeysCBOR)
	if err != nil {
		return false
	}
	for _, pubkey := range pubkeys {
		if bytes.Equal(pubkey, wanted) {
			return true
		}
	}
	return false
}

// checkRequestTimingLocal 复刻 bitfs 包内的 003 时间判断：报价过期、交付
// 截止、截止不超过报价。at 是本操作唯一一次读取的 UTC。
func checkRequestTimingLocal(terms *bitfs.ContentRequestTerms, quoteTerms *bitfs.FileQuoteTerms, at time.Time) error {
	if !at.Before(time.Unix(quoteTerms.QuoteExpiresAtUnix, 0)) {
		return fmt.Errorf("%w: file quote is expired", bitfs.ErrQuoteExpired)
	}
	if !at.Before(time.Unix(terms.DeliveryDeadlineUnix, 0)) {
		return fmt.Errorf("%w: delivery deadline has passed", bitfs.ErrDeliveryDeadline)
	}
	if terms.DeliveryDeadlineUnix > quoteTerms.QuoteExpiresAtUnix {
		return fmt.Errorf("%w: delivery deadline exceeds quote expiry", bitfs.ErrDeliveryDeadline)
	}
	return nil
}
