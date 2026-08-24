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
	"github.com/bsv8/go-bitfs/protocol"
)

// WorkflowConfig supplies the seller official BSV private key. It intentionally
// has no store, pending-request, content, backend, node, clock, signer, or
// verifier fields: those concerns belong to the calling application, and every
// signature is produced with this key through the SDK's fixed implementations.
type WorkflowConfig struct {
	// PrivateKey is the caller-parsed official BSV Go SDK private key. It
	// never enters any wire message, local result, log, or persisted structure.
	// 调用方解析好的官方 BSV 私钥；绝不进入任何 wire 报文、本地结果或日志。
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
	// 待发送的 Kind 3 预签响应 wire 报文。
	Response *pool.RefundPresignResponse
	// Opening is the seller-local presign evidence (not yet funded).
	// 卖方本地预签证据（尚未注资）；必须先保存 Opening 再发送 Response。
	Opening *pool.OpeningProof
}

// PoolFundingAcceptance is the composite result of AcceptPoolFunding.
type PoolFundingAcceptance struct {
	// Opening is the complete opening proof including the delivered FundingTransactionRaw.
	// 含已交付 FundingTransactionRaw 的完整开池证明（应用需保存）。
	Opening *pool.OpeningProof
	// InitialPayment is the initial refund payment state parsed from the
	// merged refund transaction; the application saves it as local state.
	// 从合并退款交易解析出的初始付款状态；应用作为本地状态保存。
	InitialPayment *pool.PaymentState
	// FundingTransactionRaw repeats the verified funding transaction bytes for the
	// application to broadcast through its own node adapter.
	// 已验证资金交易字节的原样副本；由应用经自己的节点适配器广播。
	FundingTransactionRaw []byte
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
	// 标识本交付所属费用池的统一关联 ID（按交易 TxID 算法派生）。
	RefundTemplateTxID pool.RefundTemplateTxID
	// PaymentAuthorizationID is the SHA-256 of the exact payment authorization CBOR.
	// 付款授权 ID = SHA-256(exact payment_authorization_cbor)，应用查找键。
	PaymentAuthorizationID protocol.PaymentAuthorizationID
	// PaymentSequence is this batch's target payment state sequence.
	// 本批次的目标付款状态序号（= 前一状态 + 1）。
	PaymentSequence uint32
	// SellerAmountAfterSatoshis is the absolute cumulative seller amount after the
	// authorized batch payment. 授权批次付款后的卖方绝对累计金额（单位 satoshi）。
	SellerAmountAfterSatoshis uint64
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
	return pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: proof.BuyerPublicKey, SellerPublicKey: proof.SellerPublicKey, ArbiterPublicKey: proof.ArbiterPublicKey})
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
	if !bytes.Equal(workflow.publicKey, proof.SellerPublicKey) {
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
	if !bytes.Equal(workflow.publicKey, request.SellerPublicKey) {
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

// CreateQuote signs the deterministic Kind 1 quote terms using system UTC read
// once at entry and returns the complete credential. Saving it is the
// application's job. The recommended filename is seller-supplied content
// description: it is sanitized first, then folded into the signed terms, so
// different filenames yield different file_quote_terms_id values.
func (workflow *Workflow) CreateQuote(_ context.Context, draft bitfs.FileQuoteTerms, recommendedFilename string) (*bitfs.SignedFileQuote, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	draft = cloneFileQuoteTermsSeller(&draft)
	// Seller 先 sanitize，再编码与签名：验证入口要求条款中的文件名已满足
	// 唯一的 sanitize 规则。
	draft.RecommendedFilename = bitfs.SanitizeRecommendedFilename(recommendedFilename)
	at := time.Now().UTC()
	if err := bitfs.ValidateFileQuoteTerms(&draft); err != nil {
		return nil, err
	}
	if !at.Before(time.Unix(draft.QuoteExpiresAtUnixSeconds, 0)) {
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
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: request.BuyerPublicKey, SellerPublicKey: request.SellerPublicKey, ArbiterPublicKey: request.ArbiterPublicKey})
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
	response := &pool.RefundPresignResponse{RefundTemplateTxID: refundTemplateTxID, SellerRefundTransactionSignature: append([]byte(nil), proof.SellerRefundTransactionSignature...)}
	return &SellerPresignResult{Response: response, Opening: proof}, nil
}

// AcceptPoolFunding verifies a 0204 funding delivery against the explicitly
// supplied seller presign evidence, completes the opening proof, and computes
// the initial refund state. The application broadcasts the returned FundingTransactionRaw
// through its own node adapter and persists Opening and InitialPayment; the
// SDK submits nothing and accepts nothing on the network's behalf.
func (workflow *Workflow) AcceptPoolFunding(ctx context.Context, presignProof *pool.OpeningProof, delivery *pool.FundingTransactionDelivery) (*PoolFundingAcceptance, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	delivery = pool.CloneFundingTransactionDelivery(delivery)
	if err := pool.ValidateFundingTransactionDelivery(delivery); err != nil {
		return nil, err
	}
	proof := pool.CloneOpeningProof(presignProof)
	if err := workflow.verifySellerOwnsOpening(ctx, proof); err != nil {
		return nil, err
	}
	if _, err := pool.ParseCanonicalTransaction(delivery.FundingTransactionRaw); err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(proof)
	if err != nil {
		return nil, err
	}
	derivedRefundTemplateTxID, err := engine.TransactionID(proof.RefundTemplateRaw)
	if err != nil {
		return nil, err
	}
	if (pool.RefundTemplateTxID(derivedRefundTemplateTxID)) != delivery.RefundTemplateTxID {
		return nil, fmt.Errorf("%w: delivery correlation ID does not match supplied opening proof", pool.ErrInvalidEvidence)
	}
	if err := engine.VerifyFundingTx(ctx, delivery.FundingTransactionRaw, proof); err != nil {
		return nil, err
	}
	proof.FundingTransactionRaw = append([]byte(nil), delivery.FundingTransactionRaw...)
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
	return &PoolFundingAcceptance{Opening: proof, InitialPayment: initial, FundingTransactionRaw: append([]byte(nil), delivery.FundingTransactionRaw...)}, nil
}

// ContentDeliveryInput carries the caller-provided content facts for a 004
// delivery beyond the wire messages themselves. The authorized hashes are
// never supplied twice: they come exclusively from the buyer-signed 003.
type ContentDeliveryInput struct {
	// ContentPayloads is the raw payload batch, ordered exactly like the hash
	// array committed in the referenced 003.
	// 原始 payload 批次，顺序与被引用 003 提交的哈希数组完全一致；整批原子交付。
	ContentPayloads [][]byte
	// Seed contains the raw seed bytes when the batch includes any block; it
	// may be empty when a pure-seed batch itself carries the seed.
	// 批次包含任何块时必须提供的 seed 原文字节；纯 seed 批次可为空。
	Seed []byte
	// BlockHeight is the caller-provided current block height, read only when
	// the opening's refund uses a block-height locktime.
	// 调用方提供的当前区块高度；仅当退款使用区块高锁定时才会读取。
	BlockHeight uint32
}

// BuildContentDelivery verifies the buyer's 003 request against the
// explicitly supplied quote, opening proof, and previous payment state,
// re-computes the PaymentAuthorizationID (SHA-256 over the exact
// payment_authorization_cbor), decodes the authorized hash batch, and
// validates every caller-supplied payload's count, order, hash,
// seed/block membership, and protocol length before recomputing and matching
// the aggregate price, target sequence, and absolute cumulative amount. Only
// then does it build content_delivery_cbor =
// deterministic-CBOR([payment_authorization_id]) and sign exactly that
// document through SignWireDocument(1, 6, ...) before encoding the five-element
// Kind 6 wire message. It returns the wire delivery together with the
// ContentDeliveryState that the application must save and pass back when
// accepting the buyer's 005 update. The SDK reads no content beyond the
// supplied bytes and holds no lease; concurrent deliveries on one pool are
// serialized by the caller.
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
	if requestTerms.SellerAmountAfterSatoshis < previous.SellerAmountSatoshis {
		return nil, nil, fmt.Errorf("%w: authorization amount cannot decrease", pool.ErrInvalidEvidence)
	}
	expectedPrice := requestTerms.SellerAmountAfterSatoshis - previous.SellerAmountSatoshis
	if err := engine.CheckPaymentCapacity(ctx, pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequence: requestTerms.PaymentSequence, SellerAmountAfterSatoshis: requestTerms.SellerAmountAfterSatoshis}); err != nil {
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
	price, err := bitfs.ContentHashesPriceSatoshis(quoteTerms, contentHashes, effectiveSeed)
	if err != nil {
		return nil, nil, fmt.Errorf("calculate aggregate content price: %w", err)
	}
	if price != expectedPrice || requestTerms.SellerAmountAfterSatoshis != previous.SellerAmountSatoshis+price {
		return nil, nil, fmt.Errorf("%w: authorization amount or sequence does not match verified content price", pool.ErrInvalidEvidence)
	}
	// 卖方通过统一 helper 对 content_delivery_cbor 签名；payload 不进入签名。
	authID, err := bitfs.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, nil, err
	}
	delivery, err := bitfs.NewSignedContentDelivery(authID, payloads, workflow.privateKey)
	if err != nil {
		return nil, nil, err
	}
	if len(delivery.ContentPayloadsCBOR) != len(payloadsCBOR) || !bytes.Equal(delivery.ContentPayloadsCBOR, payloadsCBOR) {
		return nil, nil, fmt.Errorf("%w: delivery payload encoding changed during construction", bitfs.ErrInvalidEvidence)
	}
	state := &ContentDeliveryState{
		RefundTemplateTxID:        refundTemplateTxID,
		PaymentAuthorizationID:    authID,
		PaymentSequence:           requestTerms.PaymentSequence,
		SellerAmountAfterSatoshis: requestTerms.SellerAmountAfterSatoshis,
	}
	return delivery, state, nil
}

// AcceptPayment verifies the buyer's minimal 005 payment credential against
// the explicitly supplied original signed 003 authorization, opening proof,
// previous accepted state, and the ContentDeliveryState saved after building
// 004. The application must first look up the exact original SignedContentRequest
// by the wire's PaymentAuthorizationID and pass it in; the SDK never scans
// pools or queries stores. It recomputes and compares the authorization hash,
// verifies the exact 003 buyer signature and every pool/target binding, then
// deterministically rebuilds the unsigned payment state transaction locally
// through the single BuildPaymentUpdate implementation, verifies the detached
// buyer signature over that exact rebuilt transaction, adds the seller
// signature, merges the complete transaction, and returns it with the
// authorization hash recorded in the state. Broadcasting and recording the
// outcome are the application's responsibilities; the SDK never submits
// anything.
func (workflow *Workflow) AcceptPayment(ctx context.Context, opening *pool.OpeningProof, previous *pool.PaymentState, authorization *bitfs.SignedContentRequest, deliveryState *ContentDeliveryState, update *pool.PaymentUpdate, blockHeight uint32) (*pool.SignedPayment, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	// 1. 克隆全部可变输入，并对最小 005 做结构校验。
	update = pool.ClonePaymentUpdate(update)
	if err := pool.ValidatePaymentUpdate(update); err != nil {
		return nil, err
	}
	opening = pool.CloneOpeningProof(opening)
	previous = pool.ClonePaymentState(previous)
	if authorization == nil {
		return nil, fmt.Errorf("%w: original signed content request is required", pool.ErrInvalidEvidence)
	}
	localAuthorization := bitfs.CloneSignedContentRequest(authorization)
	// 2. 重算 SHA-256(payment_authorization_cbor)，与 005 授权 ID 逐字节比较。
	authID, err := bitfs.PaymentAuthorizationID(localAuthorization.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	if update.PaymentAuthorizationID != authID {
		return nil, fmt.Errorf("%w: payment update references a different authorization than the supplied signed request", pool.ErrInvalidEvidence)
	}
	if err := workflow.verifySellerOwnsOpening(ctx, opening); err != nil {
		return nil, err
	}
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, fmt.Errorf("derive pool opening details: %w", err)
	}
	refundTemplateTxID := details.RefundTemplateTxID
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, err
	}
	// 3. 用 OpeningProof 的 Buyer 公钥验证精确 003 的买方签名。
	requestTerms, err := bitfs.VerifySignedContentRequestForOpening(localAuthorization, opening)
	if err != nil {
		return nil, fmt.Errorf("verify payment authorization: %w", err)
	}
	// 4. 从原始 003 取得 RefundTemplateTxID，与 OpeningProof 派生 ID、previous、
	// ContentDeliveryState 全部交叉比较；hash 只是查找键，池身份以证据为准。
	requestRefundTemplateTxID := pool.RefundTemplateTxID(bytes.Clone(requestTerms.RefundTemplateTxID))
	if requestRefundTemplateTxID != refundTemplateTxID {
		return nil, fmt.Errorf("%w: content request is not bound to opening proof", pool.ErrInvalidEvidence)
	}
	if previous == nil || previous.RefundTemplateTxID != refundTemplateTxID {
		return nil, pool.ErrStalePaymentSequence
	}
	if deliveryState == nil {
		return nil, fmt.Errorf("%w: content delivery state is required", pool.ErrInvalidEvidence)
	}
	if deliveryState.RefundTemplateTxID != refundTemplateTxID {
		return nil, fmt.Errorf("%w: content delivery state belongs to another pool", pool.ErrInvalidEvidence)
	}
	// 5. 卖方私钥归属已在 verifySellerOwnsOpening 检查；这里确认开池证据完整
	// 且费用池尚可接受普通前向付款（未过期）。
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	if err := checkSellerPoolNotExpired(opening, time.Now().UTC(), blockHeight); err != nil {
		return nil, fmt.Errorf("verify pool refund is still available: %w", err)
	}
	// 6. previous 必须是该 OpeningProof 下密码学完整的已接受或已仲裁状态，
	// 不信任只填序号/金额的壳。
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		if arbitratedErr := engine.VerifyArbitratedPayment(previous, opening); arbitratedErr != nil {
			return nil, fmt.Errorf("verify previous accepted payment: %w", err)
		}
	}
	// 7. 目标序号必须恰好是 previous+1，且不是最终关闭哨兵。
	if previous.PaymentSequence+1 != requestTerms.PaymentSequence || requestTerms.PaymentSequence == ^uint32(0) {
		return nil, pool.ErrStalePaymentSequence
	}
	// 8. ContentDeliveryState 与原始 003 完全一致：授权哈希、目标序号、绝对
	// 累计金额，证明本地确实为这张授权生成过 004。
	if deliveryState.PaymentAuthorizationID != authID ||
		deliveryState.PaymentSequence != requestTerms.PaymentSequence ||
		deliveryState.SellerAmountAfterSatoshis != requestTerms.SellerAmountAfterSatoshis {
		return nil, pool.ErrStalePaymentSequence
	}
	if requestTerms.SellerAmountAfterSatoshis < previous.SellerAmountSatoshis {
		return nil, fmt.Errorf("%w: authorized seller amount cannot decrease", pool.ErrInvalidEvidence)
	}
	// 9. 用 OpeningProof、previous 和 003 目标值调用唯一 BuildPaymentUpdate
	// 本地重建未签名状态交易；005 不携带也不接受任何 raw bytes。
	unsigned, err := engine.BuildPaymentUpdate(ctx, pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequence: requestTerms.PaymentSequence, SellerAmountAfterSatoshis: requestTerms.SellerAmountAfterSatoshis})
	if err != nil {
		return nil, fmt.Errorf("rebuild payment state transaction: %w", err)
	}
	if unsigned == nil || unsigned.RefundTemplateTxID != refundTemplateTxID {
		return nil, fmt.Errorf("%w: rebuilt payment state correlation mismatch", pool.ErrInvalidEvidence)
	}
	// 10. 用固定 Buyer verifier 验证 005 签名覆盖重建出的精确交易；任何错
	// opening、错 previous、错金额、错序号或错费用都会导致失败。
	if err := engine.VerifyBuyerPayment(unsigned, update.BuyerPaymentTransactionSignature, opening); err != nil {
		return nil, fmt.Errorf("verify buyer payment over rebuilt transaction: %w", err)
	}
	// 11. Seller 对同一重建交易签名，并用唯一 Buyer+Seller merge 入口生成
	// 完整 SignedPayment。
	sellerSignature, err := pool.NewSellerPoolAdapter(engine, workflow.privateKey).SignSellerPayment(ctx, unsigned, opening)
	if err != nil {
		return nil, fmt.Errorf("sign payment update: %w", err)
	}
	signed, err := engine.MergeBuyerSellerPayment(unsigned, update.BuyerPaymentTransactionSignature, sellerSignature, opening)
	if err != nil {
		return nil, fmt.Errorf("merge buyer and seller payment signatures: %w", err)
	}
	if signed == nil || len(signed.RawTx) == 0 {
		return nil, fmt.Errorf("%w: seller produced empty signed payment", pool.ErrInvalidEvidence)
	}
	// 12. 把授权哈希写入返回的 PaymentState；SDK 不保存、不广播、不宣布节点接受。
	signed.State.PaymentAuthorizationID = authID
	return signed, nil
}

// SignImmediateClose verifies the candidate structure and protocol amount
// boundaries against the opening, checks the buyer role signature with the
// fixed verifier, adds the seller signature, and merges the completed
// SignedPayment. It never reads or infers any seller database amount, does
// not judge whether the candidate matches a pending request or business
// target, and does not broadcast; accepting and broadcasting are business
// decisions. The timestamp lock uses system UTC read once at entry.
func (workflow *Workflow) SignImmediateClose(ctx context.Context, opening *pool.OpeningProof, unsigned *pool.UnsignedPayment, buyerSignature []byte, blockHeight uint32) (*pool.SignedPayment, error) {
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
	if unsigned.SellerAmountSatoshis+unsigned.BuyerAmountSatoshis+unsigned.ArbiterAmountSatoshis > details.PoolOutputSatoshis {
		return nil, fmt.Errorf("%w: immediate close outputs exceed the pool capacity", pool.ErrInvalidEvidence)
	}
	if err := engine.VerifyBuyerPayment(unsigned, buyerSignature, opening); err != nil {
		return nil, fmt.Errorf("verify buyer close signature: %w", err)
	}
	sellerSignature, err := pool.NewSellerPoolAdapter(engine, workflow.privateKey).SignSellerPayment(ctx, unsigned, opening)
	if err != nil {
		return nil, err
	}
	signed, err := engine.MergeBuyerSellerPayment(unsigned, buyerSignature, sellerSignature, opening)
	if err != nil {
		return nil, err
	}
	if signed == nil || signed.State.PaymentSequence != ^uint32(0) {
		return nil, fmt.Errorf("%w: seller close signature did not preserve final sequence", pool.ErrInvalidEvidence)
	}
	return signed, nil
}

// BuildArbitrationRequest verifies the local opening, Buyer authorization and
// existing 004 delivery, then signs only the compact Claim evidence through
// the arbitration package's shared Claim builder. It does not construct or
// sign an arbitration transaction.
func (workflow *Workflow) BuildArbitrationRequest(ctx context.Context, opening *pool.OpeningProof, authorization *bitfs.SignedContentRequest, delivery *bitfs.SignedContentDelivery, blockHeight uint32) (*arbitration.ArbitrationRequest, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	if authorization == nil || delivery == nil {
		return nil, fmt.Errorf("%w: arbitration evidence is incomplete", pool.ErrInvalidEvidence)
	}
	opening = pool.CloneOpeningProof(opening)
	authorization = bitfs.CloneSignedContentRequest(authorization)
	delivery = bitfs.CloneSignedContentDelivery(delivery)
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
	at := time.Now().UTC()
	if err := checkSellerPoolNotExpired(opening, at, blockHeight); err != nil {
		return nil, err
	}
	// 共享 Claim builder：与 Buyer 取件路径使用同一份纯函数，保证双方从相同
	// opening + 精确签名 003 得到逐字节相同的 ArbitrationClaimCBOR 与 Claim ID。
	built, err := arbitration.BuildClaimFromAuthorization(opening, authorization)
	if err != nil {
		return nil, fmt.Errorf("build arbitration Claim: %w", err)
	}
	claimAuthorization := built.Authorization
	if !at.Before(time.Unix(claimAuthorization.DeliveryDeadlineUnixSeconds, 0)) {
		return nil, fmt.Errorf("%w: delivery deadline has passed", pool.ErrInvalidEvidence)
	}
	authID, err := bitfs.PaymentAuthorizationID(authorization.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	deliveryAuthorizationID, err := bitfs.DecodeContentDeliveryDocument(delivery.ContentDeliveryCBOR)
	if err != nil {
		return nil, err
	}
	if deliveryAuthorizationID != authID {
		return nil, fmt.Errorf("%w: 004 delivery references a different authorization", pool.ErrInvalidEvidence)
	}
	if err := protocol.VerifyWireDocument(opening.SellerPublicKey, protocol.WireVersion, 6, delivery.ContentDeliveryCBOR, delivery.SellerContentDeliverySignature); err != nil {
		return nil, fmt.Errorf("%w: 004 seller signature is invalid: %v", pool.ErrInvalidEvidence, err)
	}
	payloads, err := bitfs.DecodeContentPayloads(delivery.ContentPayloadsCBOR)
	if err != nil {
		return nil, err
	}
	hashes, err := bitfs.DecodeContentHashes(claimAuthorization.ContentHashesCBOR)
	if err != nil {
		return nil, err
	}
	if len(payloads) != len(hashes) {
		return nil, fmt.Errorf("%w: 004 payload count does not match 003 hashes", pool.ErrInvalidEvidence)
	}
	for index := range payloads {
		if !bytes.Equal(sha256Bytes(payloads[index]), hashes[index]) {
			return nil, fmt.Errorf("%w: 004 payload #%d does not match 003 hash", pool.ErrInvalidEvidence, index+1)
		}
	}
	claimCBOR := built.ArbitrationClaimCBOR
	sellerClaimSignature, err := protocol.SignWireDocument(workflow.privateKey, protocol.WireVersion, 8, claimCBOR)
	if err != nil {
		return nil, fmt.Errorf("sign arbitration Claim: %w", err)
	}
	if err := protocol.VerifyWireDocument(workflow.publicKey, protocol.WireVersion, 8, claimCBOR, sellerClaimSignature); err != nil {
		return nil, fmt.Errorf("%w: generated Seller Claim signature failed verification: %v", pool.ErrInvalidEvidence, err)
	}
	return &arbitration.ArbitrationRequest{ArbitrationClaimCBOR: claimCBOR, SellerArbitrationClaimSignature: sellerClaimSignature, ContentPayloadsCBOR: delivery.ContentPayloadsCBOR}, nil
}

// CompleteArbitratedPayment verifies Kind 8/9 entirely from the Claim and the
// four-element Receipt response, independently rebuilds the paid candidate
// using the Receipt's arbiter amount, verifies the Receipt message signature
// and the Arbiter transaction signature, and only then signs and merges the
// Seller transaction signature. OpeningProof and previous state are
// deliberately absent from this API; the response carries no raw transaction.
func (workflow *Workflow) CompleteArbitratedPayment(ctx context.Context, request *arbitration.ArbitrationRequest, response *arbitration.ArbitrationResponse, blockHeight uint32) (*pool.SignedPayment, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	if request == nil || response == nil {
		return nil, fmt.Errorf("%w: arbitration evidence is incomplete", pool.ErrInvalidEvidence)
	}
	request = cloneArbitrationRequest(request)
	response = cloneArbitrationResponse(response)
	if _, err := arbitration.MarshalRequest(request); err != nil {
		return nil, err
	}
	if _, err := arbitration.MarshalResponse(response); err != nil {
		return nil, err
	}
	receipt, err := arbitration.UnmarshalReceipt(response.ArbitrationReceiptCBOR)
	if err != nil {
		return nil, err
	}
	claim, err := arbitration.UnmarshalClaim(request.ArbitrationClaimCBOR)
	if err != nil {
		return nil, err
	}
	authorization, err := bitfs.DecodePaymentAuthorization(claim.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(workflow.publicKey, keys.SellerPublicKey) {
		return nil, fmt.Errorf("%w: workflow key does not match Claim seller", pool.ErrInvalidEvidence)
	}
	if err := protocol.VerifyWireDocument(keys.BuyerPublicKey, protocol.WireVersion, 5, claim.PaymentAuthorizationCBOR, claim.BuyerPaymentAuthorizationSignature); err != nil {
		return nil, fmt.Errorf("%w: Buyer authorization signature is invalid: %v", pool.ErrInvalidEvidence, err)
	}
	if err := protocol.VerifyWireDocument(keys.SellerPublicKey, protocol.WireVersion, 8, request.ArbitrationClaimCBOR, request.SellerArbitrationClaimSignature); err != nil {
		return nil, fmt.Errorf("%w: Seller Claim signature is invalid: %v", pool.ErrInvalidEvidence, err)
	}
	payloads, err := bitfs.DecodeContentPayloads(request.ContentPayloadsCBOR)
	if err != nil {
		return nil, err
	}
	hashes, err := bitfs.DecodeContentHashes(authorization.ContentHashesCBOR)
	if err != nil {
		return nil, err
	}
	if len(payloads) != len(hashes) {
		return nil, fmt.Errorf("%w: payload count does not match 003 hashes", pool.ErrInvalidEvidence)
	}
	for index := range payloads {
		if !bytes.Equal(sha256Bytes(payloads[index]), hashes[index]) {
			return nil, fmt.Errorf("%w: payload #%d does not match 003 hash", pool.ErrInvalidEvidence, index+1)
		}
	}
	// Seller 从 Claim primitives 独立重算 Claim ID 并与回执比较，不信任传输层身份。
	localClaimID, err := arbitration.ArbitrationClaimID(request.ArbitrationClaimCBOR)
	if err != nil {
		return nil, err
	}
	if receipt.ArbitrationClaimID != localClaimID {
		return nil, fmt.Errorf("%w: receipt Claim ID does not match the independently computed Claim ID", pool.ErrInvalidEvidence)
	}
	if err := protocol.VerifyWireDocument(keys.ArbiterPublicKey, protocol.WireVersion, 9, response.ArbitrationReceiptCBOR, response.ArbiterArbitrationReceiptSignature); err != nil {
		return nil, fmt.Errorf("%w: Arbitration receipt signature is invalid: %v", pool.ErrInvalidEvidence, err)
	}
	unsigned, err := pool.BuildArbitrationPaymentFromClaim(claim.PoolOutputSatoshis, claim.PoolOutputLockingScript, claim.RefundTemplateRaw, authorization.PaymentSequence, authorization.SellerAmountAfterSatoshis, receipt.ArbiterAmountSatoshis)
	if err != nil {
		return nil, err
	}
	if err := pool.CheckArbitrationRefundNotExpired(claim.RefundTemplateRaw, blockHeight); err != nil {
		return nil, fmt.Errorf("%w: refund template is no longer available for arbitration: %v", pool.ErrInvalidEvidence, err)
	}
	authID, err := bitfs.PaymentAuthorizationID(claim.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil, err
	}
	// 先验证回执绑定的仲裁交易签名覆盖本地重建的付费 candidate，再产生 Seller 签名。
	if err := engine.VerifyArbitrationArbiterPayment(unsigned, receipt.ArbiterPaymentTransactionSignature); err != nil {
		return nil, fmt.Errorf("%w: Arbiter transaction signature is invalid: %v", pool.ErrInvalidEvidence, err)
	}
	sellerSignature, err := engine.SignArbitrationSellerPayment(ctx, unsigned, workflow.privateKey)
	if err != nil {
		return nil, err
	}
	signed, err := engine.MergeArbitratedPoolSellerArbiterSignatures(unsigned, sellerSignature, receipt.ArbiterPaymentTransactionSignature)
	if err != nil {
		return nil, err
	}
	if signed == nil || len(signed.RawTx) == 0 {
		return nil, fmt.Errorf("%w: merged arbitration transaction is empty", pool.ErrInvalidEvidence)
	}
	if signed.State.ArbiterAmountSatoshis != receipt.ArbiterAmountSatoshis || signed.State.SellerAmountSatoshis != authorization.SellerAmountAfterSatoshis {
		return nil, fmt.Errorf("%w: merged arbitration amounts do not match the receipt and Buyer terms", pool.ErrInvalidEvidence)
	}
	signed.State.PaymentAuthorizationID = authID
	return signed, nil
}

func sha256Bytes(value []byte) []byte {
	hash := sha256.Sum256(value)
	return append([]byte(nil), hash[:]...)
}

func cloneArbitrationRequest(value *arbitration.ArbitrationRequest) *arbitration.ArbitrationRequest {
	if value == nil {
		return nil
	}
	return &arbitration.ArbitrationRequest{ArbitrationClaimCBOR: append([]byte(nil), value.ArbitrationClaimCBOR...), SellerArbitrationClaimSignature: append([]byte(nil), value.SellerArbitrationClaimSignature...), ContentPayloadsCBOR: append([]byte(nil), value.ContentPayloadsCBOR...)}
}

func cloneArbitrationResponse(value *arbitration.ArbitrationResponse) *arbitration.ArbitrationResponse {
	if value == nil {
		return nil
	}
	return &arbitration.ArbitrationResponse{ArbitrationReceiptCBOR: append([]byte(nil), value.ArbitrationReceiptCBOR...), ArbiterArbitrationReceiptSignature: append([]byte(nil), value.ArbiterArbitrationReceiptSignature...)}
}

func cloneFileQuoteTermsSeller(terms *bitfs.FileQuoteTerms) bitfs.FileQuoteTerms {
	if terms == nil {
		return bitfs.FileQuoteTerms{}
	}
	cloned := *terms
	cloned.SeedHash = append([]byte(nil), terms.SeedHash...)
	cloned.BuyerPublicKey = append([]byte(nil), terms.BuyerPublicKey...)
	cloned.SupportedArbiterPublicKeysCBOR = append([]byte(nil), terms.SupportedArbiterPublicKeysCBOR...)
	return cloned
}

// checkRequestTimingLocal 复刻 bitfs 包内的 003 时间判断：报价过期、交付
// 截止、截止不超过报价。at 是本操作唯一一次读取的 UTC。
func checkRequestTimingLocal(terms *bitfs.PaymentAuthorization, quoteTerms *bitfs.FileQuoteTerms, at time.Time) error {
	if !at.Before(time.Unix(quoteTerms.QuoteExpiresAtUnixSeconds, 0)) {
		return fmt.Errorf("%w: file quote is expired", bitfs.ErrQuoteExpired)
	}
	if !at.Before(time.Unix(terms.DeliveryDeadlineUnixSeconds, 0)) {
		return fmt.Errorf("%w: delivery deadline has passed", bitfs.ErrDeliveryDeadline)
	}
	if terms.DeliveryDeadlineUnixSeconds > quoteTerms.QuoteExpiresAtUnixSeconds {
		return fmt.Errorf("%w: delivery deadline exceeds quote expiry", bitfs.ErrDeliveryDeadline)
	}
	return nil
}
