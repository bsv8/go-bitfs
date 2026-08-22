package buyer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	masterseed "github.com/bsv8/MasterSeed"
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
		Reference:      pool.Reference{RefundTemplateTxID: initial.RefundTemplateTxID, BasePaymentSequence: initial.PaymentSequence},
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

// ContentRequestInput carries the content selection and deadline facts for a
// 003 request. Quote, opening proof, previous payment state, time, and block
// height are explicit method parameters.
type ContentRequestInput struct {
	Content          bitfs.ContentRef
	ContentSize      uint64
	DeliveryDeadline bitfs.UnixSeconds
	// Seed contains the raw verified seed bytes when the requested content is
	// a block; it may be empty for seed-type content.
	Seed []byte
	// BlockHeight is the caller-provided current block height, read only when
	// the opening's refund uses a block-height locktime.
	BlockHeight uint32
}

// BuildContentRequest verifies the quote, opening ownership, previous payment
// state, content reference context, price, and balance, then signs the 003
// request with this workflow's private key. System UTC is read once at entry;
// the block height arrives from the caller. It reads no content and changes no
// pool state; whether base is the business-latest state is the caller's call.
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
	contentHash := append([]byte(nil), input.Content.Hash...)
	// 时间无关证据验证；过期判断使用本操作唯一一次读取的 at。
	terms, err := bitfs.VerifyFileQuoteEvidence(localQuote)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(workflow.publicKey, terms.BuyerPubkey) {
		return nil, fmt.Errorf("%w: signer does not match quote buyer", bitfs.ErrInvalidEvidence)
	}
	if len(contentHash) != masterseed.DigestSize {
		return nil, fmt.Errorf("%w: content hash must be 32 bytes", bitfs.ErrInvalidEvidence)
	}
	if input.DeliveryDeadline <= bitfs.UnixSeconds(at.Unix()) {
		return nil, fmt.Errorf("%w: delivery deadline is not in the future", bitfs.ErrDeliveryDeadline)
	}
	if !bytes.Equal(opening.BuyerPubKey, terms.BuyerPubkey) || !bytes.Equal(opening.SellerPubKey, localQuote.SellerPubkey) {
		return nil, fmt.Errorf("%w: verify pool participants", bitfs.ErrInvalidEvidence)
	}
	if !quoteAllowsArbiter(terms, opening.ArbiterPubKey) {
		return nil, fmt.Errorf("%w: opening arbiter is not allowed by quote", bitfs.ErrInvalidEvidence)
	}
	if previous == nil || previous.RefundTemplateTxID != refundTemplateTxID {
		return nil, bitfs.ErrStalePaymentSequence
	}
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	if previous.PaymentSequence >= uint32(^uint32(0)-1) {
		return nil, bitfs.ErrStalePaymentSequence
	}
	var seed []byte
	if input.Content.Type != bitfs.ContentSeed {
		if len(input.Seed) == 0 {
			return nil, fmt.Errorf("%w: a verified seed is required before requesting a block", bitfs.ErrContentNotInSeed)
		}
		seed = append([]byte(nil), input.Seed...)
	}
	if err := bitfs.VerifyContentReferenceContext(ctx, terms, input.Content.Type, contentHash, seed, false); err != nil {
		return nil, err
	}
	if input.Content.Type == bitfs.ContentBlock {
		matches, err := bitfs.VerifyBlockReference(ctx, terms, contentHash, seed)
		if err != nil {
			return nil, err
		}
		if !contentSizeMatchesBlock(terms.FileSize, input.ContentSize, matches) {
			return nil, fmt.Errorf("%w: content size %d does not match any committed block position", bitfs.ErrInvalidEvidence, input.ContentSize)
		}
	}
	contentSize := input.ContentSize
	if input.Content.Type == bitfs.ContentSeed {
		contentSize = 1
	}
	price, err := bitfs.ContentPriceSat(terms, input.Content.Type, contentSize)
	if err != nil {
		return nil, err
	}
	if previous.SellerAmountSat > ^uint64(0)-price {
		return nil, bitfs.ErrInsufficientBalance
	}
	quoteHash, err := bitfs.FileQuoteTermsHash(localQuote.TermsCBOR)
	if err != nil {
		return nil, err
	}
	requestTerms := &bitfs.ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		RefundTemplateTxID:    refundTemplateTxID[:],
		BasePaymentSequence:   uint64(previous.PaymentSequence),
		PaymentSequenceAfter:  uint64(previous.PaymentSequence + 1),
		SellerAmountAfterSat:  previous.SellerAmountSat + price,
		MinerFeeRateSatPerKB:  opening.MinerFeeRateSatPerKB,
		BuyerPubkey:           append([]byte(nil), terms.BuyerPubkey...),
		SellerPubkey:          append([]byte(nil), localQuote.SellerPubkey...),
		SelectedArbiterPubkey: append([]byte(nil), opening.ArbiterPubKey...),
		ContentType:           input.Content.Type,
		ContentHash:           contentHash,
		DeliveryDeadlineUnix:  int64(input.DeliveryDeadline),
	}
	return bitfs.NewSignedContentRequest(requestTerms, workflow.privateKey)
}

// contentSizeMatchesBlock checks only real match endpoints returned by
// MasterSeed. It intentionally never treats an index between FirstIndex and
// LastIndex as a match when duplicate hashes are non-contiguous.
func contentSizeMatchesBlock(fileSize, contentSize uint64, matches masterseed.BlockMatches) bool {
	if matches.MatchCount == 0 {
		return false
	}
	for _, index := range []uint64{matches.FirstIndex, matches.LastIndex} {
		expected, err := masterseed.ExpectedBlockSize(fileSize, index)
		if err == nil && expected == contentSize {
			return true
		}
	}
	return false
}

// VerifiedDelivery is the composite result of AcceptDelivery: Payload holds
// the verified content bytes for the application to persist, and Update is
// the signed 005 wire update to send to the seller.
type VerifiedDelivery struct {
	// Payload contains the verified content bytes returned by the SDK.
	Payload []byte
	// Update is the signed cumulative payment update (wire message).
	Update *pool.PaymentUpdate
}

// ContentDeliveryInput carries the caller-provided verification inputs for a
// 004 delivery beyond the wire messages themselves.
type ContentDeliveryInput struct {
	// Seed contains the raw seed bytes when the delivered content is a block;
	// it may be empty for seed-type content.
	Seed []byte
	// BlockHeight is the caller-provided current block height, read only when
	// the opening's refund uses a block-height locktime.
	BlockHeight uint32
}

// AcceptDelivery verifies the request linkage, seller signature, content hash,
// size, and seed binding of the 004 delivery, then builds and signs the next
// 005 cumulative payment update. System UTC is read once at entry; verified
// content bytes are returned as data and saving them is the application's job.
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
	requestTerms, err := bitfs.DecodeContentRequestTerms(localRequest.TermsCBOR)
	if err != nil {
		return nil, err
	}
	localQuote := bitfs.CloneSignedFileQuote(quote)
	quoteTerms, err := bitfs.DecodeFileQuoteTerms(localQuote.TermsCBOR)
	if err != nil {
		return nil, err
	}
	openingDetails, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, fmt.Errorf("derive pool opening details: %w", err)
	}
	refundTemplateTxID := pool.RefundTemplateTxID(bytes.Clone(requestTerms.RefundTemplateTxID))
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
	if openingDetails.RefundTemplateTxID != refundTemplateTxID || requestTerms.MinerFeeRateSatPerKB != opening.MinerFeeRateSatPerKB {
		return nil, fmt.Errorf("%w: content request is not bound to opening proof", bitfs.ErrInvalidEvidence)
	}
	if !bytes.Equal(opening.BuyerPubKey, quoteTerms.BuyerPubkey) || !bytes.Equal(opening.SellerPubKey, localQuote.SellerPubkey) || !bytes.Equal(opening.ArbiterPubKey, requestTerms.SelectedArbiterPubkey) {
		return nil, fmt.Errorf("%w: verify pool participants", bitfs.ErrInvalidEvidence)
	}
	seed := append([]byte(nil), input.Seed...)
	payload, requestTermsEvidence, _, err := bitfs.VerifyContentDeliveryEvidenceWithSeed(localRequest, localDelivery, localQuote, seed)
	if err != nil {
		return nil, err
	}
	// 交付验证返回的 quote terms 用于本操作唯一一次的时间判断。
	quoteTermsEvidence, err := bitfs.VerifyFileQuoteEvidence(localQuote)
	if err != nil {
		return nil, err
	}
	if err := checkRequestTimingLocal(requestTermsEvidence, quoteTermsEvidence, at); err != nil {
		return nil, err
	}
	if previous == nil || previous.PaymentSequence != uint32(requestTerms.BasePaymentSequence) {
		return nil, bitfs.ErrStalePaymentSequence
	}
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	if requestTerms.PaymentSequenceAfter != uint64(previous.PaymentSequence+1) || requestTerms.PaymentSequenceAfter > uint64(^uint32(0)-1) || requestTerms.SellerAmountAfterSat < previous.SellerAmountSat {
		return nil, bitfs.ErrStalePaymentSequence
	}
	if previous.PaymentSequence >= 0xfffffffe {
		return nil, fmt.Errorf("%w: payment sequence exhausted", bitfs.ErrStalePaymentSequence)
	}
	updateInput := pool.PaymentUpdateInput{
		Opening:              opening,
		Previous:             previous,
		PaymentSequenceAfter: previous.PaymentSequence + 1,
		SellerAmountAfterSat: requestTerms.SellerAmountAfterSat,
	}
	if err := engine.CheckPaymentCapacity(ctx, updateInput); err != nil {
		return nil, err
	}
	price, err := bitfs.ContentPriceSat(quoteTerms, requestTerms.ContentType, uint64(len(payload)))
	if err != nil {
		return nil, err
	}
	if ^uint64(0)-previous.SellerAmountSat < price || requestTerms.SellerAmountAfterSat != previous.SellerAmountSat+price {
		return nil, fmt.Errorf("%w: seller amount does not match content price", bitfs.ErrInvalidEvidence)
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
	requestHash, err := bitfs.PaymentAuthorizationHash(localRequest.TermsCBOR)
	if err != nil {
		return nil, err
	}
	update := &pool.PaymentUpdate{
		Version:                   pool.MajorVersion,
		RefundTemplateTxID:        refundTemplateTxID,
		PaymentAuthorizationHash:  requestHash[:],
		UnsignedStateTxRaw:        append([]byte(nil), unsigned.RawTx...),
		BuyerTransactionSignature: append([]byte(nil), buyerSig...),
	}
	return &VerifiedDelivery{Payload: append([]byte(nil), payload...), Update: update}, nil
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
