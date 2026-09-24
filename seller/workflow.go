package seller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

// workflow 是 Seller 角色 API（001–007）。它只持有固定的受约束 Signer 及其
// 派生公钥；没有存储、待处理请求索引、内容仓库、节点、时钟或广播副作用。
// 所有时间/高度判断使用调用方显式传入的一份 Facts。
type workflow struct {
	signer    protocol.Signer
	publicKey protocol.PublicKey
}

// newWorkflow 固定并验证 Signer 公钥后返回 Seller 角色 API。直接私钥必须经
// protocol.NewPrivateKeySigner 进入，不存在第二构造器。
func newWorkflow(signer protocol.Signer) (*workflow, error) {
	const op = "seller.newWorkflow"
	if signer == nil {
		return nil, protocol.Errorf(op, protocol.CodeSignerUnavailable, 0, "signer", "seller workflow requires a signer")
	}
	bound, err := protocol.BindSigner(signer)
	if err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 0, "signer")
	}
	publicKey := bound.PublicKey()
	return &workflow{signer: bound, publicKey: publicKey}, nil
}

// PublicKey 返回本角色的固定压缩公钥副本。
func (workflow *workflow) PublicKey() []byte {
	if workflow == nil {
		return nil
	}
	return append([]byte(nil), workflow.publicKey[:]...)
}

func (workflow *workflow) requireSelf(op string) error {
	if workflow == nil || workflow.signer == nil {
		return protocol.Errorf(op, protocol.CodeUnauthorized, 0, "workflow", "seller workflow is required")
	}
	return nil
}

func (workflow *workflow) engineFor(proof *pool.OpeningProof) (*pool.MultisigPoolEngine, error) {
	if proof == nil {
		return nil, protocol.Errorf("seller", protocol.CodeInvalidEvidence, 0, "opening_proof", "opening proof is required")
	}
	return pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: proof.BuyerPublicKey, SellerPublicKey: proof.SellerPublicKey, ArbiterPublicKey: proof.ArbiterPublicKey})
}

// ensureOwnership 把 opening evidence 绑定到本 workflow 公钥。
func (workflow *workflow) ensureOwnership(op string, proof *pool.OpeningProof) error {
	if proof == nil {
		return protocol.Errorf(op, protocol.CodeInvalidEvidence, 0, "opening_proof", "opening proof is required")
	}
	if !bytes.Equal(workflow.publicKey[:], proof.SellerPublicKey) {
		return protocol.Errorf(op, protocol.CodeUnauthorized, 0, "seller_public_key", "workflow key does not match opening seller")
	}
	return nil
}

// refundGate 是正向退款门禁：只读取锁定类型对应的那一份事实。分类由
// WrapClassified 保留——事实缺失保持 invalid_evidence，绝不误报成 expired。
func refundGate(op string, facts protocol.Facts, lockTime uint32) error {
	if err := facts.CheckRefundNotExpired(protocol.RefundLockTime(lockTime)); err != nil {
		return protocol.WrapClassified(err, op, 0, "refund_locktime")
	}
	return nil
}

// CreateQuote 以单一 QuoteDraft 签署确定性 Kind 1 条款：先 sanitize 文件名再
// 编码与签名，返回待发送 Artifact 与最终规范化 terms（展示实际签署值）。
// 唯一时间事实为 facts.Now。
func (workflow *workflow) CreateQuote(ctx context.Context, facts protocol.Facts, draft QuoteDraft) (*quoteResult, error) {
	const op = "seller.CreateQuote"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	now, err := facts.RequireNow()
	if err != nil {
		return nil, err
	}
	arbiters := make([][]byte, 0, len(draft.SupportedArbiterPublicKeys))
	for _, key := range draft.SupportedArbiterPublicKeys {
		arbiters = append(arbiters, append([]byte(nil), key[:]...))
	}
	supportedCBOR, err := content.EncodeSupportedArbiterPublicKeys(arbiters)
	if err != nil {
		return nil, err
	}
	terms := &content.FileQuoteTerms{
		SeedHash:                       append([]byte(nil), draft.SeedHash...),
		BuyerPublicKey:                 append([]byte(nil), draft.BuyerPublicKey[:]...),
		SeedPriceSatoshis:              uint64(draft.SeedPriceSatoshis),
		FullBlockPriceSatoshis:         uint64(draft.FullBlockPriceSatoshis),
		FileSizeBytes:                  draft.FileSizeBytes,
		QuoteExpiresAtUnixSeconds:      int64(draft.QuoteExpiresAtUnixSeconds),
		SupportedArbiterPublicKeysCBOR: supportedCBOR,
		RecommendedFilename:            content.SanitizeRecommendedFilename(draft.RecommendedFilename),
	}
	if err := content.ValidateFileQuoteTerms(terms); err != nil {
		return nil, invalidEvidence(err)
	}
	if !now.Before(unixSeconds(terms.QuoteExpiresAtUnixSeconds)) {
		return nil, protocol.Errorf(op, protocol.CodeExpired, 1, "quote_expires_at_unix_seconds", "file quote is expired at the supplied facts.now")
	}
	signedQuote, err := content.NewSignedFileQuote(ctx, terms, workflow.signer)
	if err != nil {
		return nil, err
	}
	finalTerms, err := content.VerifyFileQuoteEvidence(signedQuote)
	if err != nil {
		return nil, fmt.Errorf("verify generated quote: %w", err)
	}
	outbound, err := wire.EncodeFileQuote(signedQuote)
	if err != nil {
		return nil, err
	}
	return &quoteResult{Outbound: outbound, Terms: finalTerms}, nil
}

// PreparePoolOpening 验证 exact Kind 2 并计算卖方退款预签：返回待发送 Kind 3
// Artifact 与必须先持久化的 openingCheckpoint。相同的重复请求只会得到等价的
// 新鲜计算结果——SDK 不存储、不重放。
func (workflow *workflow) PreparePoolOpening(ctx context.Context, rawKind2 []byte) (*preparePoolOpeningResult, error) {
	const op = "seller.PreparePoolOpening"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, protocol.Errorf(op, protocol.CodeCanceled, 2, "ctx", "a non-nil context is required")
	}
	artifact, err := wire.ParseAs(wire.RefundPresignRequest, rawKind2)
	if err != nil {
		return nil, err
	}
	request, err := wire.DecodeRefundPresignRequest(artifact)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(workflow.publicKey[:], request.SellerPublicKey) {
		return nil, protocol.Errorf(op, protocol.CodeUnauthorized, 2, "seller_public_key", "refund presign request names another seller")
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: request.BuyerPublicKey, SellerPublicKey: request.SellerPublicKey, ArbiterPublicKey: request.ArbiterPublicKey})
	if err != nil {
		return nil, err
	}
	signature, err := pool.NewSellerPoolAdapter(engine, workflow.signer).SignSellerRefund(ctx, request)
	if err != nil {
		return nil, err
	}
	proof, err := engine.BuildOpeningProof(request, signature, nil)
	if err != nil {
		return nil, err
	}
	response := &pool.RefundPresignResponse{RefundTemplateTxID: mustRefundTemplateTxID(proof), SellerRefundTransactionSignature: append([]byte(nil), proof.SellerRefundTransactionSignature...)}
	outbound, err := wire.EncodeRefundPresignResponse(response)
	if err != nil {
		return nil, err
	}
	return &preparePoolOpeningResult{Outbound: outbound, Checkpoint: &openingCheckpoint{opening: proof}}, nil
}

// VerifyFundingDelivery 用保存的预签 checkpoint 验收 exact Kind 4：完成开池
// 证明并解析初始退款状态。返回的 FundingTransactionRaw 由应用自行广播；
// InitialPool 必须在广播决策前持久化。方法名不含 Accept/Broadcast：验收证据
// 与提交网络是两件事。
func (workflow *workflow) VerifyFundingDelivery(checkpoint *openingCheckpoint, rawKind4 []byte) (*fundingVerificationResult, error) {
	const op = "seller.VerifyFundingDelivery"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	proof := checkpoint.Opening()
	if proof == nil {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 4, "checkpoint", "persisted presign evidence is required")
	}
	if err := workflow.ensureOwnership(op, proof); err != nil {
		return nil, err
	}
	return verifyFundingDelivery(proof, rawKind4)
}

// verifyFundingDelivery 是 VerifyFunding 与 VerifyFundingDelivery 共用的纯证据
// 实现：只用调用方提供的预签证明与 exact Kind 4 完成资金交易验证、初始退款状态
// 重建与全量复核，不读取任何角色身份或签名能力。
func verifyFundingDelivery(proof *pool.OpeningProof, rawKind4 []byte) (*fundingVerificationResult, error) {
	const op = "seller.VerifyFunding"
	deliveryArtifact, err := wire.ParseAs(wire.FundingTransactionDelivery, rawKind4)
	if err != nil {
		return nil, err
	}
	delivery, err := wire.DecodeFundingTransactionDelivery(deliveryArtifact)
	if err != nil {
		return nil, err
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: proof.BuyerPublicKey, SellerPublicKey: proof.SellerPublicKey, ArbiterPublicKey: proof.ArbiterPublicKey})
	if err != nil {
		return nil, err
	}
	if _, err := pool.ParseCanonicalTransaction(delivery.FundingTransactionRaw); err != nil {
		return nil, err
	}
	derivedRefundTemplateTxID, err := engine.TransactionID(proof.RefundTemplateRaw)
	if err != nil {
		return nil, err
	}
	if (pool.RefundTemplateTxID(derivedRefundTemplateTxID)) != delivery.RefundTemplateTxID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 4, "refund_template_txid", "delivery correlation ID does not match persisted presign evidence")
	}
	if err := engine.VerifyFundingTx(delivery.FundingTransactionRaw, proof); err != nil {
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
	initial, err := engine.ParsePaymentState(initialRaw, proof)
	if err != nil {
		return nil, fmt.Errorf("parse initial pool state: %w", err)
	}
	if err := engine.VerifyAcceptedPayment(initial, proof); err != nil {
		return nil, fmt.Errorf("verify initial pool state: %w", err)
	}
	verifiedOpening, err := pool.VerifyOpeningProof(proof)
	if err != nil {
		return nil, err
	}
	if _, err := pool.VerifyPaymentState(initial, proof); err != nil {
		return nil, err
	}
	return &fundingVerificationResult{
		Opening:               verifiedOpening,
		InitialPool:           &poolCheckpoint{opening: proof, payment: initial},
		FundingTransactionRaw: append([]byte(nil), delivery.FundingTransactionRaw...),
	}, nil
}

type deliveryRequestPreflight struct {
	authorization      *content.PaymentAuthorization
	quoteTerms         *content.FileQuoteTerms
	contentHashes      [][]byte
	authorizationID    protocol.PaymentAuthorizationID
	refundTemplateTxID pool.RefundTemplateTxID
	expectedPrice      uint64
}

// preflightDeliveryRequest 是 InspectDeliveryRequest 与 DeliverContent 共用的
// 无 payload 校验：从 exact evidence 重验请求签名、报价/开池绑定、时间、当前池
// 状态、目标序号和容量，并从规范授权文档派生授权 ID 与有序内容哈希。
func preflightDeliveryRequest(op string, facts protocol.Facts, quote *content.SignedFileQuote, checkpoint *poolCheckpoint, rawKind5 []byte) (*deliveryRequestPreflight, error) {
	now, err := facts.RequireNow()
	if err != nil {
		return nil, err
	}
	requestArtifact, err := wire.ParseAs(wire.ContentRequest, rawKind5)
	if err != nil {
		return nil, err
	}
	request, err := wire.DecodeContentRequest(requestArtifact)
	if err != nil {
		return nil, err
	}
	opening := checkpoint.Opening()
	previous := checkpoint.Payment()
	localQuote := content.CloneSignedFileQuote(quote)
	if localQuote == nil || opening == nil || previous == nil {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 6, "command", "quote and pool checkpoint are required")
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: opening.BuyerPublicKey, SellerPublicKey: opening.SellerPublicKey, ArbiterPublicKey: opening.ArbiterPublicKey})
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	deliveryLockDetails, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, err
	}
	if err := refundGate(op, facts, deliveryLockDetails.RefundLockTime); err != nil {
		return nil, err
	}
	authorization, quoteTerms, err := content.VerifyContentRequestEvidence(request, localQuote, opening)
	if err != nil {
		return nil, err
	}
	if err := content.CheckContentRequestTiming(authorization, quoteTerms, now); err != nil {
		return nil, err
	}
	refundTemplateTxID := pool.RefundTemplateTxID(bytes.Clone(authorization.RefundTemplateTxID))
	if previous.RefundTemplateTxID != refundTemplateTxID || previous.PaymentSequence+1 != authorization.PaymentSequence {
		return nil, staleSequenceErr(op)
	}
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	if authorization.SellerAmountAfterSatoshis < previous.SellerAmountSatoshis {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 6, "seller_amount_after_satoshis", "authorization amount cannot decrease")
	}
	if err := engine.CheckPaymentCapacity(pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequence: authorization.PaymentSequence, SellerAmountAfterSatoshis: authorization.SellerAmountAfterSatoshis}); err != nil {
		return nil, fmt.Errorf("check delivery payment capacity: %w", err)
	}
	contentHashes, err := content.DecodeContentHashes(authorization.ContentHashesCBOR)
	if err != nil {
		return nil, err
	}
	authorizationID, err := content.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	return &deliveryRequestPreflight{
		authorization:      authorization,
		quoteTerms:         quoteTerms,
		contentHashes:      contentHashes,
		authorizationID:    authorizationID,
		refundTemplateTxID: refundTemplateTxID,
		expectedPrice:      authorization.SellerAmountAfterSatoshis - previous.SellerAmountSatoshis,
	}, nil
}

// DeliverContent 验证买方 003 全链证据后构造并签署 Kind 6：返回待发送
// Artifact 与必须先持久化的 deliveryCheckpoint（先保存后发送）。
func (workflow *workflow) DeliverContent(ctx context.Context, facts protocol.Facts, command deliveryCommand) (*deliveryResult, error) {
	const op = "seller.DeliverContent"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	opening := command.Pool.Opening()
	if err := workflow.ensureOwnership(op, opening); err != nil {
		return nil, err
	}
	preflight, err := preflightDeliveryRequest(op, facts, command.Quote, command.Pool, command.RequestRaw)
	if err != nil {
		return nil, err
	}
	previous := command.Pool.Payment()
	payloads := make([][]byte, len(command.ContentPayloads))
	for index := range command.ContentPayloads {
		payloads[index] = append([]byte(nil), command.ContentPayloads[index]...)
	}
	seed := append([]byte(nil), command.Seed...)
	effectiveSeed, err := content.VerifyContentPayloads(ctx, preflight.quoteTerms, preflight.contentHashes, payloads, seed)
	if err != nil {
		return nil, err
	}
	price, err := content.ContentHashesPriceSatoshis(ctx, preflight.quoteTerms, preflight.contentHashes, effectiveSeed)
	if err != nil {
		return nil, fmt.Errorf("calculate aggregate content price: %w", err)
	}
	if price != preflight.expectedPrice || preflight.authorization.SellerAmountAfterSatoshis != previous.SellerAmountSatoshis+price {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 6, "seller_amount_after_satoshis", "authorization amount or sequence does not match verified content price")
	}
	delivery, err := content.NewSignedContentDelivery(ctx, preflight.authorizationID, payloads, workflow.signer)
	if err != nil {
		return nil, err
	}
	outbound, err := wire.EncodeContentDelivery(delivery)
	if err != nil {
		return nil, err
	}
	checkpoint := &deliveryCheckpoint{refundTemplateTxID: preflight.refundTemplateTxID, authorizationID: preflight.authorizationID, paymentSequence: protocol.PaymentSequence(preflight.authorization.PaymentSequence), sellerAmountAfterSatoshis: protocol.Satoshis(preflight.authorization.SellerAmountAfterSatoshis)}
	return &deliveryResult{Outbound: outbound, Checkpoint: checkpoint}, nil
}

// CompletePayment 验证买方最小 Kind 7 凭证、补签并合并完整交易：返回完整交易
// （仅供应用决定是否广播）与 next pool checkpoint；SDK 不声称节点接受。
func (workflow *workflow) CompletePayment(ctx context.Context, facts protocol.Facts, command paymentCommand) (*completePaymentResult, error) {
	const op = "seller.CompletePayment"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	updateArtifact, err := wire.ParseAs(wire.PaymentUpdate, command.UpdateRaw)
	if err != nil {
		return nil, err
	}
	update, err := wire.DecodePaymentUpdate(updateArtifact)
	if err != nil {
		return nil, err
	}
	opening := command.Pool.Opening()
	previous := command.Pool.Payment()
	localAuthorization := content.CloneSignedContentRequest(command.Request)
	if localAuthorization == nil {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 7, "request", "original signed content request is required")
	}
	authID, err := content.PaymentAuthorizationID(localAuthorization.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	if update.PaymentAuthorizationID != authID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 7, "payment_authorization_id", "payment update references a different authorization than the supplied signed request")
	}
	if err := workflow.ensureOwnership(op, opening); err != nil {
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
	requestTerms, err := content.VerifySignedContentRequestForOpening(localAuthorization, opening)
	if err != nil {
		return nil, fmt.Errorf("verify payment authorization: %w", err)
	}
	requestRefundTemplateTxID := pool.RefundTemplateTxID(bytes.Clone(requestTerms.RefundTemplateTxID))
	if requestRefundTemplateTxID != refundTemplateTxID {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 7, "refund_template_txid", "content request is not bound to opening proof")
	}
	if previous == nil || previous.RefundTemplateTxID != refundTemplateTxID {
		return nil, staleSequenceErr(op)
	}
	if command.Checkpoint == nil {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 7, "checkpoint", "content delivery checkpoint is required")
	}
	if command.Checkpoint.refundTemplateTxID != refundTemplateTxID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 7, "refund_template_txid", "content delivery checkpoint belongs to another pool")
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	if err := refundGate(op, facts, details.RefundLockTime); err != nil {
		return nil, err
	}
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		if arbitratedErr := engine.VerifyArbitratedPayment(previous, opening); arbitratedErr != nil {
			return nil, fmt.Errorf("verify previous accepted payment: %w", err)
		}
	}
	if previous.PaymentSequence+1 != requestTerms.PaymentSequence || requestTerms.PaymentSequence == ^uint32(0) {
		return nil, staleSequenceErr(op)
	}
	if command.Checkpoint.authorizationID != authID ||
		command.Checkpoint.paymentSequence != protocol.PaymentSequence(requestTerms.PaymentSequence) ||
		command.Checkpoint.sellerAmountAfterSatoshis != protocol.Satoshis(requestTerms.SellerAmountAfterSatoshis) {
		return nil, staleSequenceErr(op)
	}
	if requestTerms.SellerAmountAfterSatoshis < previous.SellerAmountSatoshis {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 7, "seller_amount_after_satoshis", "authorized seller amount cannot decrease")
	}
	unsigned, err := engine.BuildPaymentUpdate(pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequence: requestTerms.PaymentSequence, SellerAmountAfterSatoshis: requestTerms.SellerAmountAfterSatoshis})
	if err != nil {
		return nil, fmt.Errorf("rebuild payment state transaction: %w", err)
	}
	if unsigned == nil || unsigned.RefundTemplateTxID != refundTemplateTxID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 7, "rebuilt_candidate", "rebuilt payment state correlation mismatch")
	}
	if err := engine.VerifyBuyerPayment(unsigned, update.BuyerPaymentTransactionSignature, opening); err != nil {
		return nil, fmt.Errorf("verify buyer payment over rebuilt transaction: %w", err)
	}
	sellerSignature, err := pool.NewSellerPoolAdapter(engine, workflow.signer).SignSellerPayment(ctx, unsigned, opening)
	if err != nil {
		return nil, fmt.Errorf("sign payment update: %w", err)
	}
	signed, err := engine.MergeBuyerSellerPayment(unsigned, update.BuyerPaymentTransactionSignature, sellerSignature, opening)
	if err != nil {
		return nil, fmt.Errorf("merge buyer and seller payment signatures: %w", err)
	}
	if signed == nil || len(signed.RawTx) == 0 {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 7, "raw_tx", "seller produced empty signed payment")
	}
	signed.State.PaymentAuthorizationID = authID
	verified, err := pool.VerifySignedTransaction(signed.RawTx, opening)
	if err != nil {
		return nil, fmt.Errorf("verify merged payment: %w", err)
	}
	next := &poolCheckpoint{opening: pool.CloneOpeningProof(opening), payment: clonePaymentState(&signed.State)}
	return &completePaymentResult{
		Transaction: verified,
		NextPool:    next,
	}, nil
}

// completePaymentResult 是 CompletePayment 的统一 Result：Transaction 是完整
// 签名交易（是否广播由应用决定）；NextPool 是合并后的本地 verified 状态。
type completePaymentResult struct {
	// Transaction 是签名完整的付款交易；广播边界属于应用。
	Transaction *pool.VerifiedSignedTransaction
	// NextPool 是本笔付款之后的池 checkpoint（verified 本地状态）。
	NextPool *poolCheckpoint
}

// CompleteClose 校验买方关闭 candidate 结构与角色签名后补签并合并完整交易。
// 它不读取任何卖方数据库金额，也不判断 candidate 是否匹配业务目标。
func (workflow *workflow) CompleteClose(ctx context.Context, facts protocol.Facts, command closeCommand) (*pool.VerifiedSignedTransaction, error) {
	const op = "seller.CompleteClose"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	unsigned := command.Unsigned
	if unsigned == nil || unsigned.PaymentSequence != ^uint32(0) {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 0, "unsigned_close", "immediate close must use the final sequence")
	}
	if command.Pool == nil || command.Pool.payment == nil {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 0, "pool_checkpoint", "seller pool checkpoint is required")
	}
	opening := command.Pool.Opening()
	if err := workflow.ensureOwnership(op, opening); err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, err
	}
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, err
	}
	if command.Pool.payment.PaymentSequence == ^uint32(0) {
		if err := engine.VerifyBuyerPayment(unsigned, command.BuyerSignature, opening); err != nil {
			return nil, protocol.WrapClassified(fmt.Errorf("verify buyer close signature: %w", err), op, 0, "buyer_close_transaction_signature")
		}
		if err := engine.PaymentStateMatchesUnsigned(command.Pool.payment, unsigned, opening); err != nil || !bytes.Equal(command.Pool.payment.BuyerTransactionSignature, command.BuyerSignature) {
			return nil, protocol.Errorf(op, protocol.CodeStateConflict, 0, "payment_sequence", "pool is already final with a different close candidate")
		}
		return pool.VerifySignedTransaction(command.Pool.payment.RawTx, opening)
	}
	if err := refundGate(op, facts, details.RefundLockTime); err != nil {
		return nil, err
	}
	if unsigned.SellerAmountSatoshis+unsigned.BuyerAmountSatoshis+unsigned.ArbiterAmountSatoshis > details.PoolOutputSatoshis {
		return nil, protocol.Errorf(op, protocol.CodeInsufficientBalance, 0, "outputs_satoshis", "immediate close outputs exceed the pool capacity")
	}
	if err := engine.VerifyBuyerPayment(unsigned, command.BuyerSignature, opening); err != nil {
		return nil, protocol.WrapClassified(fmt.Errorf("verify buyer close signature: %w", err), op, 0, "buyer_close_transaction_signature")
	}
	sellerSignature, err := pool.NewSellerPoolAdapter(engine, workflow.signer).SignSellerPayment(ctx, unsigned, opening)
	if err != nil {
		return nil, err
	}
	signed, err := engine.MergeBuyerSellerPayment(unsigned, command.BuyerSignature, sellerSignature, opening)
	if err != nil {
		return nil, err
	}
	if signed == nil || signed.State.PaymentSequence != ^uint32(0) {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 0, "payment_sequence", "seller close signature did not preserve final sequence")
	}
	return pool.VerifySignedTransaction(signed.RawTx, opening)
}

// PrepareArbitration 验证本地开池、买方授权与本方已发交付后，签署紧凑 Claim
// 证据并返回 exact Kind 8 Artifact。它不构造也不预测仲裁方响应。
func (workflow *workflow) PrepareArbitration(ctx context.Context, facts protocol.Facts, command arbitrationCommand) (wire.Artifact, error) {
	const op = "seller.PrepareArbitration"
	if err := workflow.requireSelf(op); err != nil {
		return wire.Artifact{}, err
	}
	now, err := facts.RequireNow()
	if err != nil {
		return wire.Artifact{}, err
	}
	localAuthorization := content.CloneSignedContentRequest(command.Request)
	deliveryArtifact, err := wire.ParseAs(wire.ContentDelivery, command.DeliveryRaw)
	if err != nil {
		return wire.Artifact{}, err
	}
	delivery, err := wire.DecodeContentDelivery(deliveryArtifact)
	if err != nil {
		return wire.Artifact{}, err
	}
	opening := command.Pool.Opening()
	if err := workflow.ensureOwnership(op, opening); err != nil {
		return wire.Artifact{}, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return wire.Artifact{}, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return wire.Artifact{}, err
	}
	arbLockDetails, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return wire.Artifact{}, err
	}
	if err := refundGate(op, facts, arbLockDetails.RefundLockTime); err != nil {
		return wire.Artifact{}, err
	}
	built, err := arbitration.BuildClaimFromAuthorization(opening, localAuthorization)
	if err != nil {
		return wire.Artifact{}, fmt.Errorf("build arbitration Claim: %w", err)
	}
	if !now.Before(unixSeconds(built.Authorization.DeliveryDeadlineUnixSeconds)) {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeExpired, 8, "delivery_deadline_unix_seconds", "delivery deadline has passed")
	}
	authID, err := content.PaymentAuthorizationID(localAuthorization.PaymentAuthorizationCBOR)
	if err != nil {
		return wire.Artifact{}, err
	}
	deliveryAuthorizationID, err := content.DecodeContentDeliveryDocument(delivery.ContentDeliveryCBOR)
	if err != nil {
		return wire.Artifact{}, err
	}
	if deliveryAuthorizationID != authID {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 8, "content_delivery_cbor", "delivery references a different authorization")
	}
	if err := protocol.VerifyWireDocument(opening.SellerPublicKey, protocol.WireVersion, 6, delivery.ContentDeliveryCBOR, delivery.SellerContentDeliverySignature); err != nil {
		return wire.Artifact{}, protocol.Wrap(fmt.Errorf("seller delivery signature is invalid: %v", err), op, protocol.CodeInvalidSignature, 8, "seller_content_delivery_signature")
	}
	payloads, err := content.DecodeContentPayloads(delivery.ContentPayloadsCBOR)
	if err != nil {
		return wire.Artifact{}, err
	}
	hashes, err := content.DecodeContentHashes(built.Authorization.ContentHashesCBOR)
	if err != nil {
		return wire.Artifact{}, err
	}
	if len(payloads) != len(hashes) {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 8, "payload_count", "delivery payload count does not match 003 hashes")
	}
	for index := range payloads {
		digest := sha256.Sum256(payloads[index])
		if !bytes.Equal(digest[:], hashes[index]) {
			return wire.Artifact{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 8, fmt.Sprintf("payload[%d]", index), "delivery payload #%d does not match 003 hash", index+1)
		}
	}
	claimCBOR := built.ArbitrationClaimCBOR
	sellerClaimSignature, err := protocol.SignWireDocument(ctx, workflow.signer, protocol.WireVersion, 8, claimCBOR)
	if err != nil {
		return wire.Artifact{}, fmt.Errorf("sign arbitration Claim: %w", err)
	}
	if err := protocol.VerifyWireDocument(workflow.publicKey[:], protocol.WireVersion, 8, claimCBOR, sellerClaimSignature); err != nil {
		return wire.Artifact{}, protocol.Wrap(fmt.Errorf("generated Seller Claim signature failed verification: %v", err), op, protocol.CodeInvalidSignature, 8, "seller_arbitration_claim_signature")
	}
	request := &arbitration.ArbitrationRequest{ArbitrationClaimCBOR: claimCBOR, SellerArbitrationClaimSignature: sellerClaimSignature, ContentPayloadsCBOR: delivery.ContentPayloadsCBOR}
	return wire.EncodeArbitrationRequest(request)
}

// CompleteArbitratedPayment 从 exact Kind 8/9 完整验证托管收款路径：独立重建
// paid candidate、验证回执消息签名与仲裁交易签名，然后补签卖方交易签名并合并
// 完整交易。不广播；是否入账由应用决定。
func (workflow *workflow) CompleteArbitratedPayment(ctx context.Context, facts protocol.Facts, command arbitratedPaymentCommand) (*pool.VerifiedSignedTransaction, error) {
	const op = "seller.CompleteArbitratedPayment"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	request, err := wire.ParseAs(wire.ArbitrationRequest, command.RequestRaw)
	if err != nil {
		return nil, err
	}
	localRequest, err := wire.DecodeArbitrationRequest(request)
	if err != nil {
		return nil, err
	}
	response, err := wire.ParseAs(wire.ArbitrationResponse, command.ResponseRaw)
	if err != nil {
		return nil, err
	}
	localResponse, err := wire.DecodeArbitrationResponse(response)
	if err != nil {
		return nil, err
	}
	receipt, err := arbitration.UnmarshalReceipt(localResponse.ArbitrationReceiptCBOR)
	if err != nil {
		return nil, err
	}
	claim, err := arbitration.UnmarshalClaim(localRequest.ArbitrationClaimCBOR)
	if err != nil {
		return nil, err
	}
	authorization, err := content.DecodePaymentAuthorization(claim.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(workflow.publicKey[:], keys.SellerPublicKey) {
		return nil, protocol.Errorf(op, protocol.CodeUnauthorized, 9, "seller_public_key", "workflow key does not match Claim seller")
	}
	if err := protocol.VerifyWireDocument(keys.BuyerPublicKey, protocol.WireVersion, 5, claim.PaymentAuthorizationCBOR, claim.BuyerPaymentAuthorizationSignature); err != nil {
		return nil, protocol.Wrap(fmt.Errorf("buyer authorization signature is invalid: %v", err), op, protocol.CodeInvalidSignature, 9, "buyer_payment_authorization_signature")
	}
	if err := protocol.VerifyWireDocument(keys.SellerPublicKey, protocol.WireVersion, 8, localRequest.ArbitrationClaimCBOR, localRequest.SellerArbitrationClaimSignature); err != nil {
		return nil, protocol.Wrap(fmt.Errorf("Seller Claim signature is invalid: %v", err), op, protocol.CodeInvalidSignature, 9, "seller_arbitration_claim_signature")
	}
	payloads, err := content.DecodeContentPayloads(localRequest.ContentPayloadsCBOR)
	if err != nil {
		return nil, err
	}
	if len(command.DeliveryPayloadsCBOR) > 0 && !bytes.Equal(command.DeliveryPayloadsCBOR, localRequest.ContentPayloadsCBOR) {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 9, "content_payloads_cbor", "stored delivery payload bundle does not match the custodied attachment")
	}
	hashes, err := content.DecodeContentHashes(authorization.ContentHashesCBOR)
	if err != nil {
		return nil, err
	}
	if len(payloads) != len(hashes) {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 9, "payload_count", "payload count does not match 003 hashes")
	}
	for index := range payloads {
		digest := sha256.Sum256(payloads[index])
		if !bytes.Equal(digest[:], hashes[index]) {
			return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 9, fmt.Sprintf("payload[%d]", index), "payload #%d does not match 003 hash", index+1)
		}
	}
	// 卖方从 Claim primitives 独立重算 Claim ID 并与回执比较，不信任传输层身份。
	localClaimID, err := arbitration.ArbitrationClaimID(localRequest.ArbitrationClaimCBOR)
	if err != nil {
		return nil, err
	}
	if receipt.ArbitrationClaimID != localClaimID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 9, "arbitration_claim_id", "receipt Claim ID does not match the independently computed Claim ID")
	}
	if err := protocol.VerifyWireDocument(keys.ArbiterPublicKey, protocol.WireVersion, 9, localResponse.ArbitrationReceiptCBOR, localResponse.ArbiterArbitrationReceiptSignature); err != nil {
		return nil, protocol.Wrap(fmt.Errorf("arbitration receipt signature is invalid: %v", err), op, protocol.CodeInvalidSignature, 9, "arbiter_arbitration_receipt_signature")
	}
	unsigned, err := pool.BuildArbitrationPaymentFromClaim(claim.PoolOutputSatoshis, claim.PoolOutputLockingScript, claim.RefundTemplateRaw, authorization.PaymentSequence, authorization.SellerAmountAfterSatoshis, receipt.ArbiterAmountSatoshis)
	if err != nil {
		return nil, err
	}
	claimLockTime, err := pool.RefundTemplateLockTime(claim.RefundTemplateRaw)
	if err != nil {
		return nil, err
	}
	if err := facts.CheckRefundNotExpired(claimLockTime); err != nil {
		return nil, protocol.WrapClassified(fmt.Errorf("refund template is no longer available for arbitration: %w", err), op, 9, "refund_template_raw")
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil, err
	}
	// 先验证回执绑定的仲裁交易签名覆盖本地重建的付费 candidate，再产生卖方签名。
	if err := engine.VerifyArbitrationArbiterPayment(unsigned, receipt.ArbiterPaymentTransactionSignature); err != nil {
		return nil, protocol.Wrap(fmt.Errorf("arbiter transaction signature is invalid: %v", err), op, protocol.CodeInvalidSignature, 9, "arbiter_payment_transaction_signature")
	}
	sellerSignature, err := engine.SignArbitrationSellerPayment(ctx, unsigned, workflow.signer)
	if err != nil {
		return nil, err
	}
	// 仲裁合并走 pool 的原子入口：双签名验证、canonical 合并与 Verified 构造
	// 全部在 pool 内部一次完成，不依赖任何调用顺序约定。
	verified, err := pool.CompleteArbitratedTransaction(unsigned, sellerSignature, receipt.ArbiterPaymentTransactionSignature)
	if err != nil {
		return nil, err
	}
	if verified.State() == nil || verified.State().ArbiterAmountSatoshis != receipt.ArbiterAmountSatoshis || verified.State().SellerAmountSatoshis != authorization.SellerAmountAfterSatoshis {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 9, "amounts_satoshis", "merged arbitration amounts do not match the receipt and buyer terms")
	}
	return verified, nil
}

// ---- 包内小工具 ----

func invalidEvidence(err error) error {
	return protocol.Wrap(err, "seller", protocol.CodeInvalidEvidence, 1, "")
}

func staleSequenceErr(op string) error {
	return protocol.Errorf(op, protocol.CodeStateConflict, 0, "payment_sequence", "stale payment sequence")
}

func mustRefundTemplateTxID(proof *pool.OpeningProof) pool.RefundTemplateTxID {
	id, err := pool.DeriveRefundTemplateTxID(proof)
	if err != nil {
		return pool.RefundTemplateTxID{}
	}
	return id
}

func clonePaymentState(state *pool.PaymentState) *pool.PaymentState {
	if state == nil {
		return nil
	}
	return pool.ClonePaymentState(state)
}
