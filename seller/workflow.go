package seller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/internal/refundlock"
	"github.com/bsv8/go-bitfs/pool"
)

// WorkflowConfig supplies the seller official BSV private key. It intentionally
// has no store, pending-request, content, backend, node, clock, signer, or
// verifier fields: those concerns belong to the calling application, and every
// signature is produced with this key through the SDK's fixed implementations.
type WorkflowConfig struct {
	// PrivateKey is the caller-parsed official BSV Go SDK private key. It
	// never enters any wire message, local result, log, or persisted structure.
	PrivateKey *ec.PrivateKey
}

// Workflow is the stateless seller protocol orchestrator for 001–007. Apart
// from the private key and the compressed public key derived from it, it holds
// no session state.
type Workflow struct {
	privateKey *ec.PrivateKey
	publicKey  []byte
}

// SellerPresignResult is the composite result of PresignPoolOpening:
// Response is the 0202 wire message to send back to the buyer, and Opening is
// the local presign evidence that the application must save before sending
// Response, because later steps (0205, arbitration) need it again.
type SellerPresignResult struct {
	// Response is the signed 0202 refund-presign response (wire message).
	Response *pool.RefundPresignResponse
	// Opening is the seller-local presign evidence (not yet funded).
	Opening *pool.OpeningProof
}

// PoolFundingAcceptance is the composite result of AcceptPoolFunding.
type PoolFundingAcceptance struct {
	// Opening is the complete opening proof including the delivered FundingTx.
	Opening *pool.OpeningProof
	// InitialPayment is the initial refund payment state parsed from the
	// merged refund transaction; the application saves it as local state.
	InitialPayment *pool.PaymentState
	// FundingTx repeats the verified funding transaction bytes for the
	// application to broadcast through its own node adapter.
	FundingTx []byte
}

// ContentDeliveryState is the lock-free local role state returned by
// BuildContentDelivery. It records exactly the protocol context needed to
// validate the buyer's 005 update for this delivery batch: the target payment
// sequence and the absolute cumulative seller amount the authorization
// commits to. The application saves it after generating 004 and passes it
// back into AcceptPayment together with the explicitly supplied previous
// PaymentState; it carries no owner, lease, acquire, held, release, or expiry
// semantics and never duplicates base-state values.
type ContentDeliveryState struct {
	// RefundTemplateTxID identifies the pool this delivery belongs to.
	RefundTemplateTxID pool.RefundTemplateTxID
	// PaymentAuthorizationHash is the SHA-256 of the signed 003 terms CBOR.
	PaymentAuthorizationHash pool.Hash32
	// PaymentSequence is this batch's target payment state sequence.
	PaymentSequence uint32
	// SellerAmountAfterSat is the absolute cumulative seller amount after the
	// authorized batch payment.
	SellerAmountAfterSat uint64
}

// NewWorkflow validates the seller private key and returns a stateless workflow.
func NewWorkflow(config WorkflowConfig) (*Workflow, error) {
	if config.PrivateKey == nil {
		return nil, errors.New("seller workflow requires a private key")
	}
	return &Workflow{privateKey: config.PrivateKey, publicKey: config.PrivateKey.PubKey().Compressed()}, nil
}

func (workflow *Workflow) engineFor(proof *pool.OpeningProof) (*pool.MultisigPoolEngine, error) {
	if proof == nil {
		return nil, fmt.Errorf("%w: opening proof is required", pool.ErrInvalidEvidence)
	}
	return pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey})
}

// verifySellerOwnsOpening binds caller-supplied opening evidence to the
// compressed public key derived from this workflow's private key. A
// RefundTemplateTxID alone never authorizes another seller's state or
// signatures, so every method re-checks this binding.
func (workflow *Workflow) verifySellerOwnsOpening(_ context.Context, proof *pool.OpeningProof) error {
	if workflow == nil || workflow.privateKey == nil {
		return fmt.Errorf("%w: seller private key is required", pool.ErrInvalidEvidence)
	}
	if proof == nil {
		return fmt.Errorf("%w: opening proof is required", pool.ErrInvalidEvidence)
	}
	if !bytes.Equal(workflow.publicKey, proof.SellerPubKey) {
		return fmt.Errorf("%w: workflow key does not match opening seller", pool.ErrInvalidEvidence)
	}
	return nil
}

func (workflow *Workflow) verifySellerOwnsRequest(_ context.Context, request *pool.RefundPresignRequest) error {
	if workflow == nil || workflow.privateKey == nil {
		return fmt.Errorf("%w: seller private key is required", pool.ErrInvalidEvidence)
	}
	if request == nil {
		return fmt.Errorf("%w: refund presign request is required", pool.ErrInvalidEvidence)
	}
	if !bytes.Equal(workflow.publicKey, request.SellerPubKey) {
		return fmt.Errorf("%w: workflow key does not match refund request seller", pool.ErrInvalidEvidence)
	}
	return nil
}

// checkSellerPoolNotExpired 与 buyer 侧同义：用操作唯一一次读取的 at 或
// 调用方传入的区块高度对退款锁定做纯本地比较。
func checkSellerPoolNotExpired(opening *pool.OpeningProof, at time.Time, blockHeight uint32) error {
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return err
	}
	if err := refundlock.CheckNotExpired(details.RefundLockTime, at, blockHeight); err != nil {
		return fmt.Errorf("%w: %s", pool.ErrInvalidEvidence, err)
	}
	return nil
}

// CreateQuote signs deterministic 001 quote terms using system UTC read once
// at entry and returns the complete credential. Saving it is the application's
// job. The recommended filename is display metadata and is not part of the
// signature.
func (workflow *Workflow) CreateQuote(_ context.Context, draft bitfs.FileQuoteTerms, recommendedFilename string) (*bitfs.SignedFileQuote, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	draft = cloneFileQuoteTermsSeller(&draft)
	at := time.Now().UTC()
	if err := bitfs.ValidateFileQuoteTerms(&draft); err != nil {
		return nil, err
	}
	if !at.Before(time.Unix(draft.QuoteExpiresAtUnix, 0)) {
		return nil, fmt.Errorf("%w: file quote is expired", bitfs.ErrQuoteExpired)
	}
	quote, err := bitfs.NewSignedFileQuote(&draft, workflow.privateKey, recommendedFilename)
	if err != nil {
		return nil, err
	}
	if _, err := bitfs.VerifyFileQuoteEvidence(quote); err != nil {
		return nil, fmt.Errorf("verify generated quote: %w", err)
	}
	return quote, nil
}

// PresignPoolOpening verifies a 0201 request and computes the seller's refund
// signature plus the presign-form OpeningProof. The application must save the
// returned Opening before sending Response, because 0205 and arbitration need
// it again. Nothing is stored or replayed by the SDK: identical requests
// simply produce an equivalent fresh computation.
func (workflow *Workflow) PresignPoolOpening(ctx context.Context, request *pool.RefundPresignRequest) (*SellerPresignResult, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	request = pool.CloneRefundPresignRequest(request)
	if err := pool.ValidateRefundPresignRequest(request); err != nil {
		return nil, err
	}
	if err := workflow.verifySellerOwnsRequest(ctx, request); err != nil {
		return nil, err
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: request.BuyerPubKey, SellerPubKey: request.SellerPubKey, ArbiterPubKey: request.ArbiterPubKey})
	if err != nil {
		return nil, err
	}
	sig, err := pool.NewSellerPoolAdapter(engine, workflow.privateKey).SignSellerRefund(ctx, request)
	if err != nil {
		return nil, err
	}
	proof, err := engine.BuildOpeningProof(ctx, request, sig, nil)
	if err != nil {
		return nil, err
	}
	refundTemplateTxID, err := pool.DeriveRefundTemplateTxID(ctx, proof)
	if err != nil {
		return nil, err
	}
	response := &pool.RefundPresignResponse{Version: pool.MajorVersion, RefundTemplateTxID: refundTemplateTxID, SellerRefundSignature: append([]byte(nil), proof.SellerRefundSignature...)}
	return &SellerPresignResult{Response: response, Opening: proof}, nil
}

// AcceptPoolFunding verifies a 0204 funding delivery against the explicitly
// supplied seller presign evidence, completes the opening proof, and computes
// the initial refund state. The application broadcasts the returned FundingTx
// through its own node adapter and persists Opening and InitialPayment; the
// SDK submits nothing and accepts nothing on the network's behalf.
func (workflow *Workflow) AcceptPoolFunding(ctx context.Context, presignProof *pool.OpeningProof, delivery *pool.FundingTxDelivery) (*PoolFundingAcceptance, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	delivery = pool.CloneFundingTxDelivery(delivery)
	if err := pool.ValidateFundingTxDelivery(delivery); err != nil {
		return nil, err
	}
	proof := pool.CloneOpeningProof(presignProof)
	if err := workflow.verifySellerOwnsOpening(ctx, proof); err != nil {
		return nil, err
	}
	if _, err := pool.ParseCanonicalTransaction(delivery.FundingTx); err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(proof)
	if err != nil {
		return nil, err
	}
	derivedRefundTemplateTxID, err := engine.TransactionID(proof.RefundTx)
	if err != nil {
		return nil, err
	}
	if (pool.RefundTemplateTxID(derivedRefundTemplateTxID)) != delivery.RefundTemplateTxID {
		return nil, fmt.Errorf("%w: delivery correlation ID does not match supplied opening proof", pool.ErrInvalidEvidence)
	}
	if err := engine.VerifyFundingTx(ctx, delivery.FundingTx, proof); err != nil {
		return nil, err
	}
	proof.FundingTx = append([]byte(nil), delivery.FundingTx...)
	if err := engine.VerifyOpening(proof); err != nil {
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
	if err := engine.VerifyAcceptedPayment(initial, proof); err != nil {
		return nil, fmt.Errorf("verify initial pool state: %w", err)
	}
	return &PoolFundingAcceptance{Opening: proof, InitialPayment: initial, FundingTx: append([]byte(nil), delivery.FundingTx...)}, nil
}

// ContentDeliveryInput carries the caller-provided content facts for a 004
// delivery beyond the wire messages themselves. The authorized hashes are
// never supplied twice: they come exclusively from the buyer-signed 003.
type ContentDeliveryInput struct {
	// ContentPayloads is the raw payload batch, ordered exactly like the hash
	// array committed in the referenced 003.
	ContentPayloads [][]byte
	// Seed contains the raw seed bytes when the batch includes any block; it
	// may be empty when a pure-seed batch itself carries the seed.
	Seed []byte
	// BlockHeight is the caller-provided current block height, read only when
	// the opening's refund uses a block-height locktime.
	BlockHeight uint32
}

// BuildContentDelivery verifies the buyer's 003 request against the
// explicitly supplied quote, opening proof, and previous payment state,
// re-computes the payment authorization hash, decodes the authorized hash
// batch, and validates every caller-supplied payload's count, order, hash,
// seed/block membership, and protocol length before recomputing and matching
// the aggregate price, target sequence, and absolute cumulative amount. Only
// then does it sign the exact 32-byte authorization hash with this workflow's
// private key through the fixed SignMessage path and encode the four-element
// 004. It returns the wire delivery together with the ContentDeliveryState
// that the application must save and pass back when accepting the buyer's 005
// update. The SDK reads no content beyond the supplied bytes and holds no
// lease; concurrent deliveries on one pool are serialized by the caller.
func (workflow *Workflow) BuildContentDelivery(ctx context.Context, quote *bitfs.SignedFileQuote, opening *pool.OpeningProof, previous *pool.PaymentState, request *bitfs.SignedContentRequest, input ContentDeliveryInput) (*bitfs.SignedContentDelivery, *ContentDeliveryState, error) {
	if workflow == nil {
		return nil, nil, errors.New("seller workflow is required")
	}
	request = bitfs.CloneSignedContentRequest(request)
	if request == nil {
		return nil, nil, fmt.Errorf("%w: signed content request is required", bitfs.ErrInvalidEvidence)
	}
	localQuote := bitfs.CloneSignedFileQuote(quote)
	opening = pool.CloneOpeningProof(opening)
	previous = pool.ClonePaymentState(previous)
	at := time.Now().UTC()
	if err := workflow.verifySellerOwnsOpening(ctx, opening); err != nil {
		return nil, nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	if err := checkSellerPoolNotExpired(opening, at, input.BlockHeight); err != nil {
		return nil, nil, fmt.Errorf("verify pool refund is still available: %w", err)
	}
	// 完整时间无关证据验证：报价签名、池绑定、买方签名、报价哈希与角色绑定。
	// 时间判断复用本操作唯一一次读取的 at，不重复读钟。
	requestTerms, quoteTerms, err := bitfs.VerifyContentRequestEvidence(request, localQuote, opening)
	if err != nil {
		return nil, nil, err
	}
	if err := checkRequestTimingLocal(requestTerms, quoteTerms, at); err != nil {
		return nil, nil, err
	}
	refundTemplateTxID := pool.RefundTemplateTxID(bytes.Clone(requestTerms.RefundTemplateTxID))
	if previous == nil || previous.RefundTemplateTxID != refundTemplateTxID || previous.PaymentSequence+1 != requestTerms.PaymentSequence {
		return nil, nil, pool.ErrStalePaymentSequence
	}
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, nil, fmt.Errorf("verify current pool state: %w", err)
	}
	if requestTerms.SellerAmountAfterSat < previous.SellerAmountSat {
		return nil, nil, fmt.Errorf("%w: authorization amount cannot decrease", pool.ErrInvalidEvidence)
	}
	expectedPrice := requestTerms.SellerAmountAfterSat - previous.SellerAmountSat
	if err := engine.CheckPaymentCapacity(ctx, pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequence: requestTerms.PaymentSequence, SellerAmountAfterSat: requestTerms.SellerAmountAfterSat}); err != nil {
		return nil, nil, fmt.Errorf("check delivery payment capacity: %w", err)
	}
	contentHashes, err := bitfs.DecodeContentHashes(requestTerms.ContentHashesCBOR)
	if err != nil {
		return nil, nil, err
	}
	payloads := make([][]byte, len(input.ContentPayloads))
	for index := range input.ContentPayloads {
		payloads[index] = append([]byte(nil), input.ContentPayloads[index]...)
	}
	// 编码入口同时强制 1..64 数量、非空与最大长度约束，并产出规范子 CBOR。
	payloadsCBOR, err := bitfs.EncodeContentPayloads(payloads)
	if err != nil {
		return nil, nil, err
	}
	seed := append([]byte(nil), input.Seed...)
	effectiveSeed, err := bitfs.VerifyContentPayloadsContext(ctx, quoteTerms, contentHashes, payloads, seed)
	if err != nil {
		return nil, nil, err
	}
	price, err := bitfs.ContentHashesPriceSat(quoteTerms, contentHashes, effectiveSeed)
	if err != nil {
		return nil, nil, fmt.Errorf("calculate aggregate content price: %w", err)
	}
	if price != expectedPrice || requestTerms.SellerAmountAfterSat != previous.SellerAmountSat+price {
		return nil, nil, fmt.Errorf("%w: authorization amount or sequence does not match verified content price", pool.ErrInvalidEvidence)
	}
	// 卖方只对精确 32 字节授权哈希做裸消息签名；payload 不进入签名。
	authHash, err := bitfs.PaymentAuthorizationHash(request.TermsCBOR)
	if err != nil {
		return nil, nil, err
	}
	delivery, err := bitfs.NewSignedContentDelivery(authHash[:], payloads, workflow.privateKey)
	if err != nil {
		return nil, nil, err
	}
	if len(delivery.ContentPayloadsCBOR) != len(payloadsCBOR) || !bytes.Equal(delivery.ContentPayloadsCBOR, payloadsCBOR) {
		return nil, nil, fmt.Errorf("%w: delivery payload encoding changed during construction", bitfs.ErrInvalidEvidence)
	}
	state := &ContentDeliveryState{
		RefundTemplateTxID:       refundTemplateTxID,
		PaymentAuthorizationHash: poolHash32Seller(authHash[:]),
		PaymentSequence:          requestTerms.PaymentSequence,
		SellerAmountAfterSat:     requestTerms.SellerAmountAfterSat,
	}
	return delivery, state, nil
}

// AcceptPayment verifies the buyer's 005 update against the explicitly
// supplied opening proof, previous accepted state, and the ContentDeliveryState
// saved after building 004, adds the seller signature, merges the complete
// transaction, and returns it. Broadcasting and recording the outcome are the
// application's responsibilities; the SDK never submits anything.
func (workflow *Workflow) AcceptPayment(ctx context.Context, opening *pool.OpeningProof, previous *pool.PaymentState, deliveryState *ContentDeliveryState, update *pool.PaymentUpdate, blockHeight uint32) (*pool.SignedPayment, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	update = pool.ClonePaymentUpdate(update)
	if err := pool.ValidatePaymentUpdate(update); err != nil {
		return nil, err
	}
	opening = pool.CloneOpeningProof(opening)
	previous = pool.ClonePaymentState(previous)
	if err := workflow.verifySellerOwnsOpening(ctx, opening); err != nil {
		return nil, err
	}
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, fmt.Errorf("derive pool opening details: %w", err)
	}
	refundTemplateTxID := details.RefundTemplateTxID
	if refundTemplateTxID != update.RefundTemplateTxID {
		return nil, fmt.Errorf("%w: explicit correlation ID does not match opening evidence", pool.ErrInvalidEvidence)
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	if err := checkSellerPoolNotExpired(opening, time.Now().UTC(), blockHeight); err != nil {
		return nil, fmt.Errorf("verify pool refund is still available: %w", err)
	}
	unsigned, err := engine.ParseUnsignedPayment(ctx, append([]byte(nil), update.UnsignedStateTxRaw...), opening)
	if err != nil {
		return nil, fmt.Errorf("parse unsigned payment state: %w", err)
	}
	if unsigned == nil {
		return nil, fmt.Errorf("%w: empty unsigned payment state", pool.ErrInvalidEvidence)
	}
	if unsigned.RefundTemplateTxID != refundTemplateTxID {
		return nil, fmt.Errorf("%w: payment state correlation mismatch", pool.ErrInvalidEvidence)
	}
	if err := engine.VerifyBuyerPayment(unsigned, update.BuyerTransactionSignature, opening); err != nil {
		return nil, fmt.Errorf("verify buyer payment: %w", err)
	}
	if deliveryState == nil {
		return nil, fmt.Errorf("%w: content delivery state is required", pool.ErrInvalidEvidence)
	}
	if previous == nil {
		return nil, pool.ErrStalePaymentSequence
	}
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify previous accepted payment: %w", err)
	}
	if unsigned.SellerAmountSat < previous.SellerAmountSat {
		return nil, fmt.Errorf("%w: seller amount cannot decrease", pool.ErrInvalidEvidence)
	}
	requestHash := poolHash32Seller(update.PaymentAuthorizationHash)
	// DeliveryState 只记录目标：池 ID、授权哈希、目标序号和绝对累计金额。
	if deliveryState.RefundTemplateTxID != unsigned.RefundTemplateTxID || deliveryState.PaymentAuthorizationHash != requestHash {
		return nil, pool.ErrStalePaymentSequence
	}
	if previous.PaymentSequence+1 != deliveryState.PaymentSequence || unsigned.PaymentSequence != deliveryState.PaymentSequence {
		return nil, pool.ErrStalePaymentSequence
	}
	if unsigned.SellerAmountSat != deliveryState.SellerAmountAfterSat {
		return nil, fmt.Errorf("%w: payment seller amount does not match the authorized absolute amount", pool.ErrInvalidEvidence)
	}
	sellerSig, err := pool.NewSellerPoolAdapter(engine, workflow.privateKey).SignSellerPayment(ctx, unsigned, opening)
	if err != nil {
		return nil, fmt.Errorf("sign payment update: %w", err)
	}
	signed, err := engine.MergeBuyerSellerPayment(unsigned, update.BuyerTransactionSignature, sellerSig, opening)
	if err != nil {
		return nil, fmt.Errorf("merge buyer and seller payment signatures: %w", err)
	}
	if signed == nil || len(signed.RawTx) == 0 {
		return nil, fmt.Errorf("%w: seller produced empty signed payment", pool.ErrInvalidEvidence)
	}
	signed.State.PaymentAuthorizationHash = requestHash
	return signed, nil
}

// SignImmediateClose verifies the candidate structure and protocol amount
// boundaries against the opening, checks the buyer role signature with the
// fixed verifier, adds the seller signature, and merges the completed
// SignedPayment. It never reads or infers any seller database amount, does
// not judge whether the candidate matches a pending request or business
// target, and does not broadcast; accepting and broadcasting are business
// decisions. The timestamp lock uses system UTC read once at entry.
func (workflow *Workflow) SignImmediateClose(ctx context.Context, opening *pool.OpeningProof, unsigned *pool.UnsignedPayment, buyerSig []byte, blockHeight uint32) (*pool.SignedPayment, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	if unsigned == nil || unsigned.PaymentSequence != ^uint32(0) {
		return nil, fmt.Errorf("%w: immediate close must use the final sequence", pool.ErrInvalidEvidence)
	}
	opening = pool.CloneOpeningProof(opening)
	if err := workflow.verifySellerOwnsOpening(ctx, opening); err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, err
	}
	if err := checkSellerPoolNotExpired(opening, time.Now().UTC(), blockHeight); err != nil {
		return nil, err
	}
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, err
	}
	if unsigned.SellerAmountSat+unsigned.BuyerAmountSat+unsigned.ArbiterAmountSat > details.PoolOutputSatoshis {
		return nil, fmt.Errorf("%w: immediate close outputs exceed the pool capacity", pool.ErrInvalidEvidence)
	}
	if err := engine.VerifyBuyerPayment(unsigned, buyerSig, opening); err != nil {
		return nil, fmt.Errorf("verify buyer close signature: %w", err)
	}
	sellerSig, err := pool.NewSellerPoolAdapter(engine, workflow.privateKey).SignSellerPayment(ctx, unsigned, opening)
	if err != nil {
		return nil, err
	}
	signed, err := engine.MergeBuyerSellerPayment(unsigned, buyerSig, sellerSig, opening)
	if err != nil {
		return nil, err
	}
	if signed == nil || signed.State.PaymentSequence != ^uint32(0) {
		return nil, fmt.Errorf("%w: seller close signature did not preserve final sequence", pool.ErrInvalidEvidence)
	}
	return signed, nil
}

// BuildArbitrationRequest verifies the retained signed 003 authorization and
// latest state, constructs the authorized candidate transaction, signs it,
// and packages everything into the 007 evidence request. It never constructs
// a replacement candidate outside the authorization and never sends anything.
func (workflow *Workflow) BuildArbitrationRequest(ctx context.Context, opening *pool.OpeningProof, authorization *bitfs.SignedContentRequest, base *pool.PaymentState, blockHeight uint32) (*arbitration.ArbitrationRequest, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	if authorization == nil {
		return nil, fmt.Errorf("%w: arbitration evidence is incomplete", pool.ErrInvalidEvidence)
	}
	opening = pool.CloneOpeningProof(opening)
	base = pool.ClonePaymentState(base)
	// 007 携带 OpeningProof：角色与费率全部从证据恢复，003 只做池绑定与
	// 买方签名验证。
	terms, err := bitfs.VerifySignedContentRequestForOpening(authorization, opening)
	if err != nil {
		return nil, fmt.Errorf("verify payment authorization: %w", err)
	}
	refundTemplateTxID := pool.RefundTemplateTxID(bytes.Clone(terms.RefundTemplateTxID))
	if err := workflow.verifySellerOwnsOpening(ctx, opening); err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, err
	}
	if err := checkSellerPoolNotExpired(opening, time.Now().UTC(), blockHeight); err != nil {
		return nil, err
	}
	if base == nil || base.RefundTemplateTxID != refundTemplateTxID || base.PaymentSequence+1 != terms.PaymentSequence {
		return nil, fmt.Errorf("%w: authorization does not match supplied base state", pool.ErrInvalidEvidence)
	}
	if err := engine.VerifyAcceptedPayment(base, opening); err != nil {
		if arbitrationErr := engine.VerifyArbitratedPayment(base, opening); arbitrationErr != nil {
			return nil, err
		}
	}
	unsigned, err := engine.BuildPaymentUpdate(ctx, pool.PaymentUpdateInput{Opening: opening, Previous: base, PaymentSequence: terms.PaymentSequence, SellerAmountAfterSat: terms.SellerAmountAfterSat})
	if err != nil {
		return nil, err
	}
	sellerSig, err := pool.NewSellerPoolAdapter(engine, workflow.privateKey).SignSellerArbitrationCandidate(ctx, unsigned, opening)
	if err != nil {
		return nil, err
	}
	openingCBOR, err := pool.EncodeOpeningProof(opening)
	if err != nil {
		return nil, err
	}
	authCBOR, err := bitfs.EncodeSignedContentRequest(authorization)
	if err != nil {
		return nil, err
	}
	return &arbitration.ArbitrationRequest{Version: arbitration.MajorVersion, RefundTemplateTxID: refundTemplateTxID, PoolOpeningProofCBOR: openingCBOR, PaymentAuthorizationCBOR: authCBOR, UnsignedStateTxRaw: append([]byte(nil), unsigned.RawTx...), SellerTransactionSignature: sellerSig}, nil
}

// CompleteArbitratedPayment verifies the 007 response hashes and arbiter
// signature against the explicitly supplied opening proof and previous state,
// merges the seller and arbiter signatures over the authorized unsigned state,
// and returns the completed SignedPayment. Broadcasting and recording the
// outcome are the application's responsibilities.
func (workflow *Workflow) CompleteArbitratedPayment(ctx context.Context, opening *pool.OpeningProof, previous *pool.PaymentState, request *arbitration.ArbitrationRequest, response *arbitration.ArbitrationResponse, blockHeight uint32) (*pool.SignedPayment, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	if request == nil || response == nil {
		return nil, fmt.Errorf("%w: arbitration evidence is incomplete", pool.ErrInvalidEvidence)
	}
	if _, err := arbitration.MarshalRequest(request); err != nil {
		return nil, err
	}
	if _, err := arbitration.MarshalResponse(response); err != nil {
		return nil, err
	}
	authorization, err := bitfs.DecodeSignedContentRequest(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	// 唯一真值：PaymentAuthorizationHash = SHA-256(003 TermsCBOR)。
	// 响应必须绑定与 004/005 相同的授权哈希；完整外壳哈希不是授权哈希。
	authHash, err := bitfs.PaymentAuthorizationHash(authorization.TermsCBOR)
	if err != nil {
		return nil, err
	}
	txHash := sha256.Sum256(request.UnsignedStateTxRaw)
	if !bytes.Equal(authHash[:], response.PaymentAuthorizationHash) || !bytes.Equal(txHash[:], response.UnsignedStateTxHash) {
		return nil, fmt.Errorf("%w: arbiter response does not bind request evidence", pool.ErrInvalidEvidence)
	}
	if response.RefundTemplateTxID != request.RefundTemplateTxID {
		return nil, fmt.Errorf("%w: arbiter response does not bind the original request correlation ID", pool.ErrInvalidEvidence)
	}
	proof := pool.CloneOpeningProof(opening)
	if err := workflow.verifySellerOwnsOpening(ctx, proof); err != nil {
		return nil, err
	}
	details, err := pool.DeriveOpeningDetails(proof)
	if err != nil {
		return nil, err
	}
	if details.RefundTemplateTxID != request.RefundTemplateTxID {
		return nil, fmt.Errorf("%w: arbitration request correlation ID does not match opening evidence", pool.ErrInvalidEvidence)
	}
	terms, err := bitfs.VerifySignedContentRequestForOpening(authorization, proof)
	if err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(proof)
	if err != nil {
		return nil, err
	}
	if err := checkSellerPoolNotExpired(proof, time.Now().UTC(), blockHeight); err != nil {
		return nil, err
	}
	unsigned, err := engine.ParseUnsignedPayment(ctx, request.UnsignedStateTxRaw, proof)
	if err != nil {
		return nil, err
	}
	if unsigned.PaymentSequence != terms.PaymentSequence || unsigned.SellerAmountSat != terms.SellerAmountAfterSat {
		return nil, fmt.Errorf("%w: arbitration candidate does not match payment authorization", pool.ErrInvalidEvidence)
	}
	if err := engine.VerifySellerPayment(unsigned, request.SellerTransactionSignature, proof); err != nil {
		return nil, err
	}
	previous = pool.ClonePaymentState(previous)
	if previous == nil {
		return nil, pool.ErrStalePaymentSequence
	}
	if err := engine.VerifyAcceptedPayment(previous, proof); err != nil {
		if arbitrationErr := engine.VerifyArbitratedPayment(previous, proof); arbitrationErr != nil {
			return nil, fmt.Errorf("verify previous accepted payment: %w", err)
		}
	}
	if previous.PaymentSequence+1 != terms.PaymentSequence ||
		unsigned.PaymentSequence != terms.PaymentSequence {
		return nil, pool.ErrStalePaymentSequence
	}
	if previous.SellerAmountSat > terms.SellerAmountAfterSat {
		return nil, fmt.Errorf("%w: arbitration candidate cannot reduce seller amount", pool.ErrInvalidEvidence)
	}
	signed, err := engine.MergeSellerArbiterPayment(unsigned, request.SellerTransactionSignature, response.ArbiterTransactionSignature, proof)
	if err != nil {
		return nil, err
	}
	if signed == nil || len(signed.RawTx) == 0 {
		return nil, fmt.Errorf("%w: arbiter returned empty transaction", pool.ErrInvalidEvidence)
	}
	signed.State.PaymentAuthorizationHash = hash32ToPool(authHash)
	return signed, nil
}

func hash32ToPool(value bitfs.Hash32) pool.Hash32 { return pool.Hash32(value) }

func poolHash32Seller(raw []byte) pool.Hash32 {
	var result pool.Hash32
	copy(result[:], raw)
	return result
}

func cloneFileQuoteTermsSeller(terms *bitfs.FileQuoteTerms) bitfs.FileQuoteTerms {
	if terms == nil {
		return bitfs.FileQuoteTerms{}
	}
	cloned := *terms
	cloned.SeedHash = append([]byte(nil), terms.SeedHash...)
	cloned.BuyerPubkey = append([]byte(nil), terms.BuyerPubkey...)
	cloned.SupportedArbiterPubkeysCBOR = append([]byte(nil), terms.SupportedArbiterPubkeysCBOR...)
	return cloned
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
