package buyer

import (
	"bytes"
	"context"
	"fmt"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

// workflow 是 Buyer 角色 API（001–006 与 008 取回）。它只持有固定的受约束
// Signer 及其派生公钥；没有存储、网络、节点、时钟或广播副作用。所有时间与
// 高度判断使用调用方显式传入的一份 Facts；签名一律由 SDK 构造 digest 后交给
// Signer 并固定自验。
type workflow struct {
	signer    protocol.Signer
	publicKey protocol.PublicKey
}

// newWorkflow 固定并验证 Signer 公钥后返回 Buyer 角色 API。直接私钥必须经
// protocol.NewPrivateKeySigner 进入，不存在第二构造器。
func newWorkflow(signer protocol.Signer) (*workflow, error) {
	const op = "buyer.newWorkflow"
	if signer == nil {
		return nil, protocol.Errorf(op, protocol.CodeSignerUnavailable, 0, "signer", "buyer workflow requires a signer")
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
	if workflow == nil {
		return protocol.Errorf(op, protocol.CodeUnauthorized, 0, "workflow", "buyer workflow is required")
	}
	return nil
}

func (workflow *workflow) engineFor(proof *pool.OpeningProof) (*pool.MultisigPoolEngine, error) {
	if proof == nil {
		return nil, protocol.Errorf("buyer", protocol.CodeInvalidEvidence, 0, "opening_proof", "opening proof is required")
	}
	return pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: proof.BuyerPublicKey, SellerPublicKey: proof.SellerPublicKey, ArbiterPublicKey: proof.ArbiterPublicKey})
}

// AcceptQuote 严格解析 exact Kind 1 bytes，验签、过期判断（唯一时间事实为
// facts.Now）与买方归属绑定全部通过后，返回不可变 VerifiedQuote。本操作是
// 纯验证：不签名、无长计算，因此不接收 context。应用决定保存位置。
func (workflow *workflow) AcceptQuote(facts protocol.Facts, rawKind1 []byte) (*content.VerifiedQuote, error) {
	const op = "buyer.AcceptQuote"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	artifact, err := wire.ParseAs(wire.FileQuote, rawKind1)
	if err != nil {
		return nil, err
	}
	quote, err := wire.DecodeFileQuote(artifact)
	if err != nil {
		return nil, err
	}
	return content.VerifyQuoteForBuyer(quote, facts, workflow.publicKey[:])
}

// PreparePoolOpening 构造并签署 Kind 2 预签请求：返回待发送 Artifact 与必须
// 先持久化的 openingCheckpoint。本操作不含任何时间/高度判断（纯交易构造），
// 因此不接收 Facts，也不接收无用参数。资金交易原文只存在于 checkpoint；SDK 不持久化。
func (workflow *workflow) PreparePoolOpening(ctx context.Context, command prepareOpeningCommand) (*preparePoolOpeningResult, error) {
	const op = "buyer.PreparePoolOpening"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: workflow.publicKey[:], SellerPublicKey: command.SellerPublicKey[:], ArbiterPublicKey: command.ArbiterPublicKey[:]})
	if err != nil {
		return nil, err
	}
	request, err := pool.NewBuyerPoolAdapter(engine, workflow.signer).BuildRefundPresignRequest(ctx, pool.OpeningInput{
		FundingTransactionRaw:           append([]byte(nil), command.FundingTransactionRaw...),
		ExpiryLockTime:                  uint32(command.ExpiryLockTime),
		MinerFeeRateSatoshisPerKilobyte: uint64(command.MinerFeeRateSatoshisPerKilobyte),
		SellerPublicKey:                 command.SellerPublicKey[:],
		ArbiterPublicKey:                command.ArbiterPublicKey[:],
	})
	if err != nil {
		return nil, err
	}
	refundTemplateTxID, err := pool.DeriveRefundTemplateTxIDFromRequest(request)
	if err != nil {
		return nil, err
	}
	outbound, err := wire.EncodeRefundPresignRequest(request)
	if err != nil {
		return nil, err
	}
	checkpoint := &openingCheckpoint{refundTemplateTxID: refundTemplateTxID, request: pool.CloneRefundPresignRequest(request), fundingTransactionRaw: append([]byte(nil), command.FundingTransactionRaw...)}
	return &preparePoolOpeningResult{Outbound: outbound, Checkpoint: checkpoint}, nil
}

// CompletePoolOpening 用保存的 openingCheckpoint 验收 exact Kind 3：重派生池
// ID 并拒绝任何错配，验卖方预签，产出 verified opening + 初始池 checkpoint。
// 纯验证路径：不接收 context。
func (workflow *workflow) CompletePoolOpening(checkpoint *openingCheckpoint, rawKind3 []byte) (*completeOpeningResult, error) {
	const op = "buyer.CompletePoolOpening"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	response, err := wire.ParseAs(wire.RefundPresignResponse, rawKind3)
	if err != nil {
		return nil, err
	}
	presignResponse, err := wire.DecodeRefundPresignResponse(response)
	if err != nil {
		return nil, err
	}
	if checkpoint == nil || checkpoint.request == nil {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 3, "checkpoint", "buyer opening checkpoint with its request is required")
	}
	localRequest := pool.CloneRefundPresignRequest(checkpoint.request)
	computed, err := pool.DeriveRefundTemplateTxIDFromRequest(localRequest)
	if err != nil {
		return nil, err
	}
	if computed != checkpoint.refundTemplateTxID || computed != presignResponse.RefundTemplateTxID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 3, "refund_template_txid", "presign response does not match the persisted opening evidence")
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: localRequest.BuyerPublicKey, SellerPublicKey: localRequest.SellerPublicKey, ArbiterPublicKey: localRequest.ArbiterPublicKey})
	if err != nil {
		return nil, err
	}
	proof, err := engine.BuildOpeningProof(localRequest, presignResponse.SellerRefundTransactionSignature, checkpoint.fundingTransactionRaw)
	if err != nil {
		return nil, protocol.Wrap(fmt.Errorf("build canonical opening proof: %v", err), op, protocol.CodeInvalidEvidence, 3, "")
	}
	if err := ensureOwnership(workflow.publicKey[:], proof); err != nil {
		return nil, err
	}
	initialRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		return nil, protocol.Wrap(fmt.Errorf("assemble initial refund state: %v", err), op, protocol.CodeInvalidEvidence, 3, "")
	}
	initial, err := engine.ParsePaymentState(initialRaw, proof)
	if err != nil {
		return nil, protocol.Wrap(fmt.Errorf("parse initial pool state: %v", err), op, protocol.CodeInvalidEvidence, 3, "")
	}
	if initial.PaymentSequence != 2 || initial.SellerAmountSatoshis != 0 || initial.ArbiterAmountSatoshis != 0 {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 3, "payment_state", "refund transaction is not the initial pool state")
	}
	verifiedOpening, err := pool.VerifyOpeningProof(proof)
	if err != nil {
		return nil, err
	}
	if _, err := pool.VerifyPaymentState(initial, proof); err != nil {
		return nil, err
	}
	return &completeOpeningResult{
		Opening:     verifiedOpening,
		InitialPool: &poolCheckpoint{opening: proof, payment: initial},
	}, nil
}

// PrepareFundingDelivery 把 verified opening 携带的资金交易打包成 Kind 4
// Artifact；纯打包路径，不接收 context；不广播资金交易——广播边界属于应用。
func (workflow *workflow) PrepareFundingDelivery(poolCheckpoint *poolCheckpoint) (wire.Artifact, error) {
	const op = "buyer.PrepareFundingDelivery"
	if err := workflow.requireSelf(op); err != nil {
		return wire.Artifact{}, err
	}
	opening := poolCheckpoint.Opening()
	if err := ensureOwnership(workflow.publicKey[:], opening); err != nil {
		return wire.Artifact{}, err
	}
	refundTemplateTxID, err := pool.DeriveRefundTemplateTxID(opening)
	if err != nil {
		return wire.Artifact{}, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return wire.Artifact{}, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return wire.Artifact{}, protocol.Wrap(fmt.Errorf("opening proof is invalid: %v", err), op, protocol.CodeInvalidEvidence, 4, "opening_proof")
	}
	if len(opening.FundingTransactionRaw) == 0 {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 4, "funding_transaction_raw", "complete funding transaction is required")
	}
	delivery := &pool.FundingTransactionDelivery{RefundTemplateTxID: refundTemplateTxID, FundingTransactionRaw: append([]byte(nil), opening.FundingTransactionRaw...)}
	return wire.EncodeFundingTransactionDelivery(delivery)
}

// RequestContent 验证报价/池/批次上下文/聚合价格/余额后签署 003：返回待发送
// Kind 5 Artifact、授权 typed ID 与必须先持久化的 authorizationCheckpoint。
func (workflow *workflow) RequestContent(ctx context.Context, facts protocol.Facts, command requestContentCommand) (*requestContentResult, error) {
	const op = "buyer.RequestContent"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	now, err := facts.RequireNow()
	if err != nil {
		return nil, err
	}
	opening := command.Pool.Opening()
	previous := command.Pool.Payment()
	if command.Quote == nil || opening == nil || previous == nil {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "command", "verified quote and pool checkpoint are required")
	}
	openingDetails, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, fmt.Errorf("derive pool opening details: %w", err)
	}
	refundTemplateTxID := openingDetails.RefundTemplateTxID
	if err := ensureOwnership(workflow.publicKey[:], opening); err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, fmt.Errorf("build pool engine: %w", err)
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	openingLockDetails, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, err
	}
	if err := facts.CheckRefundNotExpired(protocol.RefundLockTime(openingLockDetails.RefundLockTime)); err != nil {
		return nil, protocol.WrapClassified(err, op, 5, "refund_locktime")
	}
	terms := command.Quote.Terms()
	// 时间无关证据已由 AcceptQuote 完成；这里做角色绑定与本操作唯一一次的
	// 显式时间比较。
	if !bytes.Equal(terms.BuyerPublicKey, workflow.publicKey[:]) {
		return nil, protocol.Errorf(op, protocol.CodeUnauthorized, 5, "buyer_public_key", "signer does not match quote buyer")
	}
	if int64(command.DeliveryDeadline) <= now.Unix() {
		return nil, protocol.Errorf(op, protocol.CodeExpired, 5, "delivery_deadline_unix_seconds", "delivery deadline is not in the future")
	}
	if !now.Before(command.Quote.ExpiresAt()) {
		return nil, protocol.Errorf(op, protocol.CodeExpired, 5, "quote_expires_at_unix_seconds", "file quote is expired")
	}
	if int64(command.DeliveryDeadline) > command.Quote.ExpiresAt().Unix() {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "delivery_deadline_unix_seconds", "delivery deadline exceeds quote expiry")
	}
	if !bytes.Equal(opening.BuyerPublicKey, terms.BuyerPublicKey) || !bytes.Equal(opening.SellerPublicKey, command.Quote.SellerPublicKey()) {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "participant_public_keys", "pool participants do not match quote")
	}
	if !command.Quote.AllowsArbiter(opening.ArbiterPublicKey) {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 5, "supported_arbiter_public_keys", "opening arbiter is not allowed by quote")
	}
	if previous.RefundTemplateTxID != refundTemplateTxID || previous.PaymentSequence+1 == 0 {
		return nil, staleSequenceErr(op)
	}
	if previous.PaymentSequence >= ^uint32(0)-1 {
		return nil, staleSequenceErr(op)
	}
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	targetSequence := previous.PaymentSequence + 1
	contentHashes := make([][]byte, len(command.ContentHashes))
	for index, hash := range command.ContentHashes {
		contentHashes[index] = append([]byte(nil), hash...)
	}
	contentHashesCBOR, err := content.EncodeContentHashes(contentHashes)
	if err != nil {
		return nil, err
	}
	seed := append([]byte(nil), command.Seed...)
	price, err := content.ContentHashesPriceSatoshis(ctx, terms, contentHashes, seed)
	if err != nil {
		return nil, err
	}
	if previous.SellerAmountSatoshis > ^uint64(0)-price {
		return nil, protocol.Errorf(op, protocol.CodeInsufficientBalance, 5, "seller_amount_after_satoshis", "aggregate price exceeds remaining pool balance")
	}
	sellerAmountAfter := previous.SellerAmountSatoshis + price
	if err := engine.CheckPaymentCapacity(pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequence: targetSequence, SellerAmountAfterSatoshis: sellerAmountAfter}); err != nil {
		return nil, err
	}
	requestTerms := &content.PaymentAuthorization{
		FileQuoteTermsID:            command.Quote.ID(),
		RefundTemplateTxID:          refundTemplateTxID[:],
		PaymentSequence:             targetSequence,
		SellerAmountAfterSatoshis:   sellerAmountAfter,
		ContentHashesCBOR:           contentHashesCBOR,
		DeliveryDeadlineUnixSeconds: int64(command.DeliveryDeadline),
	}
	signedRequest, err := content.NewSignedContentRequest(ctx, requestTerms, workflow.signer)
	if err != nil {
		return nil, err
	}
	authID, err := content.PaymentAuthorizationID(signedRequest.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	outbound, err := wire.EncodeContentRequest(signedRequest)
	if err != nil {
		return nil, err
	}
	return &requestContentResult{
		Outbound:        outbound,
		AuthorizationID: authID,
		Checkpoint:      &authorizationCheckpoint{authorizationID: authID, request: signedRequest},
	}, nil
}

// VerifyDeliveryAndPreparePayment 验收 exact Kind 6 并产生整个批次的唯一
// Kind 7 签名凭证。方法名显式暴露"会产生买方交易签名"；先保存 payloads 与
// Result 再发送 Outbound。
func (workflow *workflow) VerifyDeliveryAndPreparePayment(ctx context.Context, facts protocol.Facts, command verifyDeliveryCommand) (*paymentPreparationResult, error) {
	const op = "buyer.VerifyDeliveryAndPreparePayment"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	now, err := facts.RequireNow()
	if err != nil {
		return nil, err
	}
	deliveryArtifact, err := wire.ParseAs(wire.ContentDelivery, command.DeliveryRaw)
	if err != nil {
		return nil, err
	}
	delivery, err := wire.DecodeContentDelivery(deliveryArtifact)
	if err != nil {
		return nil, err
	}
	if command.Pool == nil || command.Pool.Opening() == nil || command.Request == nil || command.Request.Request() == nil {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 6, "command", "pool checkpoint and persisted authorization are required")
	}
	opening := command.Pool.Opening()
	previous := command.Pool.Payment()
	localRequest := command.Request.Request()
	if err := ensureOwnership(workflow.publicKey[:], opening); err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	openingLockDetails, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, err
	}
	if err := facts.CheckRefundNotExpired(protocol.RefundLockTime(openingLockDetails.RefundLockTime)); err != nil {
		return nil, protocol.WrapClassified(err, op, 6, "refund_locktime")
	}
	requestTerms, quoteTerms, err := content.VerifyContentRequestEvidence(localRequest, command.Quote.Quote(), opening)
	if err != nil {
		return nil, err
	}
	refundTemplateTxID := pool.RefundTemplateTxID(bytes.Clone(requestTerms.RefundTemplateTxID))
	openingDetails, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, fmt.Errorf("derive pool opening details: %w", err)
	}
	if openingDetails.RefundTemplateTxID != refundTemplateTxID {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 6, "refund_template_txid", "content request is not bound to opening proof")
	}
	// 本操作唯一一份显式时间事实同时用于报价过期与交付截止判断。
	if err := content.CheckContentRequestTiming(requestTerms, quoteTerms, now); err != nil {
		return nil, err
	}
	// 重新计算 003 授权 ID 并与 content_delivery_cbor 绑定值逐字节比较。
	requestID := command.Request.AuthorizationID()
	recomputedID, err := content.PaymentAuthorizationID(localRequest.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	if recomputedID != requestID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 6, "payment_authorization_id", "persisted authorization does not match its exact bytes")
	}
	deliveryAuthorizationID, err := content.DecodeContentDeliveryDocument(delivery.ContentDeliveryCBOR)
	if err != nil {
		return nil, err
	}
	if deliveryAuthorizationID != requestID {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 6, "content_delivery_cbor", "delivery does not reference supplied request")
	}
	contentHashes, err := content.DecodeContentHashes(requestTerms.ContentHashesCBOR)
	if err != nil {
		return nil, err
	}
	payloads, err := content.DecodeContentPayloads(delivery.ContentPayloadsCBOR)
	if err != nil {
		return nil, err
	}
	seed := append([]byte(nil), command.Seed...)
	effectiveSeed, err := content.VerifyContentPayloads(ctx, quoteTerms, contentHashes, payloads, seed)
	if err != nil {
		return nil, err
	}
	if previous == nil || previous.RefundTemplateTxID != refundTemplateTxID || previous.PaymentSequence+1 != requestTerms.PaymentSequence {
		return nil, staleSequenceErr(op)
	}
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	if previous.PaymentSequence >= ^uint32(0)-1 {
		return nil, staleSequenceErr(op)
	}
	price, err := content.ContentHashesPriceSatoshis(ctx, quoteTerms, contentHashes, effectiveSeed)
	if err != nil {
		return nil, err
	}
	if previous.SellerAmountSatoshis > ^uint64(0)-price || requestTerms.SellerAmountAfterSatoshis != previous.SellerAmountSatoshis+price {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 7, "seller_amount_after_satoshis", "seller amount does not match aggregate content price")
	}
	updateInput := pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequence: requestTerms.PaymentSequence, SellerAmountAfterSatoshis: requestTerms.SellerAmountAfterSatoshis}
	if err := engine.CheckPaymentCapacity(updateInput); err != nil {
		return nil, err
	}
	unsigned, err := engine.BuildPaymentUpdate(updateInput)
	if err != nil {
		return nil, fmt.Errorf("build payment update: %w", err)
	}
	buyerSignature, err := pool.NewBuyerPoolAdapter(engine, workflow.signer).SignBuyerPayment(ctx, unsigned, opening)
	if err != nil {
		return nil, fmt.Errorf("sign payment update: %w", err)
	}
	if err := engine.VerifyBuyerPayment(unsigned, buyerSignature, opening); err != nil {
		return nil, fmt.Errorf("verify buyer payment: %w", err)
	}
	if unsigned == nil || unsigned.RefundTemplateTxID != refundTemplateTxID || unsigned.PaymentSequence <= previous.PaymentSequence {
		return nil, staleSequenceErr(op)
	}
	update := &pool.PaymentUpdate{PaymentAuthorizationID: requestID, BuyerPaymentTransactionSignature: append([]byte(nil), buyerSignature...)}
	outbound, err := wire.EncodePaymentUpdate(update)
	if err != nil {
		return nil, err
	}
	verifiedPayloads := make([][]byte, len(payloads))
	for index := range payloads {
		verifiedPayloads[index] = append([]byte(nil), payloads[index]...)
	}
	return &paymentPreparationResult{Payloads: verifiedPayloads, Outbound: outbound, NextCandidate: unsigned}, nil
}

// PrepareClose 从调用方选定的基准状态与目标金额构造未签名关闭 candidate 和
// 买方 detached 签名。SDK 不声称 base 是业务最新，也不判断目标金额是否符合
// 订单或账本；不广播。
func (workflow *workflow) PrepareClose(ctx context.Context, facts protocol.Facts, command prepareCloseCommand) (*closePreparationResult, error) {
	const op = "buyer.PrepareClose"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	opening := command.Pool.Opening()
	if err := ensureOwnership(workflow.publicKey[:], opening); err != nil {
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
	if err := facts.CheckRefundNotExpired(protocol.RefundLockTime(details.RefundLockTime)); err != nil {
		return nil, protocol.WrapClassified(err, op, 0, "refund_locktime")
	}
	base := pool.ClonePaymentState(command.Base)
	if base == nil {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 0, "base_payment_state", "base payment state is required")
	}
	unsigned, err := engine.BuildImmediateClose(pool.CloseInput{Opening: opening, Base: base, SellerAmountAfterSatoshis: uint64(command.TargetSellerAmountSatoshis)})
	if err != nil {
		return nil, err
	}
	buyerSignature, err := pool.NewBuyerPoolAdapter(engine, workflow.signer).SignBuyerPayment(ctx, unsigned, opening)
	if err != nil {
		return nil, err
	}
	if unsigned == nil || unsigned.PaymentSequence != ^uint32(0) {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 0, "payment_sequence", "immediate close is not final")
	}
	if err := engine.VerifyBuyerPayment(unsigned, buyerSignature, opening); err != nil {
		return nil, fmt.Errorf("verify immediate close: %w", err)
	}
	return &closePreparationResult{Unsigned: unsigned, BuyerSignature: buyerSignature}, nil
}

// VerifyCompletedClose 验证卖方完整关闭交易在给定 opening 下密码学、结构与
// 交易关系全部正确，返回不可变 Complete 结果；不声称已广播或已确认。
func (workflow *workflow) VerifyCompletedClose(command verifyCloseCommand) (*pool.VerifiedSignedTransaction, error) {
	const op = "buyer.VerifyCompletedClose"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	closePayment := pool.CloneSignedPayment(command.Close)
	if closePayment == nil || closePayment.State.PaymentSequence != ^uint32(0) || len(closePayment.RawTx) == 0 || !bytes.Equal(closePayment.State.RawTx, closePayment.RawTx) {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 0, "close_payment", "final signed payment is required")
	}
	opening := command.Pool.Opening()
	if err := ensureOwnership(workflow.publicKey[:], opening); err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyCompletedFinalPayment(closePayment, opening); err != nil {
		return nil, fmt.Errorf("verify final payment: %w", err)
	}
	verified, err := pool.VerifySignedTransaction(closePayment.RawTx, opening)
	if err != nil {
		return nil, fmt.Errorf("verify final payment: %w", err)
	}
	return verified, nil
}

// BuildMaturedRefund 在显式事实判定退款到期后合并双方退款签名，返回可广播的
// verified refund transaction；是否广播由应用决定。
func (workflow *workflow) BuildMaturedRefund(facts protocol.Facts, poolCheckpoint *poolCheckpoint) (*pool.VerifiedSignedTransaction, error) {
	const op = "buyer.BuildMaturedRefund"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	opening := poolCheckpoint.Opening()
	if err := ensureOwnership(workflow.publicKey[:], opening); err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, err
	}
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, err
	}
	if err := facts.CheckRefundMatured(protocol.RefundLockTime(details.RefundLockTime)); err != nil {
		return nil, protocol.WrapClassified(err, op, 0, "refund_locktime")
	}
	raw, err := engine.BuildRefundSubmission(opening)
	if err != nil {
		return nil, err
	}
	txID, err := engine.TransactionID(opening.RefundTemplateRaw)
	if err != nil {
		return nil, err
	}
	state, err := engine.ParsePaymentState(raw, opening)
	if err != nil {
		return nil, fmt.Errorf("parse refund payment state: %w", err)
	}
	if state.RefundTemplateTxID != (pool.RefundTemplateTxID(txID)) {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 0, "refund_template_txid", "refund transaction does not match opening correlation ID")
	}
	if _, err := pool.VerifyPaymentState(state, opening); err != nil {
		return nil, err
	}
	return pool.VerifySignedTransaction(raw, opening)
}

// RequestArbitratedContent 为一条托管记录构造 exact Kind 10 Artifact：默认入口
// 由 SDK 生成安全随机 nonce；网络超时重试必须原样重放已持久化的 Artifact，
// 绝不能重新调用本方法生成新 nonce。
func (workflow *workflow) RequestArbitratedContent(ctx context.Context, command arbitrationRetrievalCommand) (wire.Artifact, error) {
	const op = "buyer.RequestArbitratedContent"
	if err := workflow.requireSelf(op); err != nil {
		return wire.Artifact{}, err
	}
	nonce, err := protocol.GenerateRetrievalNonce()
	if err != nil {
		return wire.Artifact{}, err
	}
	return workflow.buildRetrievalRequest(ctx, command, nonce)
}

// arbitrationRetrievalCommand 携带构造 Kind 10 所需的本地证据：opening（经池
// checkpoint）+ exact 已签 003。
type arbitrationRetrievalCommand struct {
	// Pool 是当前池 checkpoint。
	Pool *poolCheckpoint
	// Authorization 是 exact 已签 003 的 checkpoint。
	Authorization *authorizationCheckpoint
}

func (workflow *workflow) buildRetrievalRequest(ctx context.Context, command arbitrationRetrievalCommand, nonce protocol.RetrievalNonce) (wire.Artifact, error) {
	const op = "buyer.buildRetrievalRequest"
	opening := command.Pool.Opening()
	authorization := command.Authorization.Request()
	if authorization == nil {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 10, "authorization", "exact signed 003 is required")
	}
	if err := ensureOwnership(workflow.publicKey[:], opening); err != nil {
		return wire.Artifact{}, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return wire.Artifact{}, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return wire.Artifact{}, fmt.Errorf("verify pool opening proof: %w", err)
	}
	if _, err := content.VerifySignedContentRequestForOpening(authorization, opening); err != nil {
		return wire.Artifact{}, fmt.Errorf("verify payment authorization: %w", err)
	}
	built, err := arbitration.BuildClaimFromAuthorization(opening, authorization)
	if err != nil {
		return wire.Artifact{}, fmt.Errorf("build arbitration Claim: %w", err)
	}
	request, err := arbitration.NewContentRetrievalRequest(ctx, built.ArbitrationClaimID, nonce, workflow.signer)
	if err != nil {
		return wire.Artifact{}, fmt.Errorf("build content retrieval request: %w", err)
	}
	return wire.EncodeContentRetrievalRequest(request)
}

// VerifyArbitratedContent 时间无关地验收 exact Kind 10/11：available 分支额外
// 复核 payload 归属与价格；unavailable 分支作为已验签协议结果返回。过期报价、
// 截止或退款锁定绝不拒绝已签托管证据；available 不生成 Kind 7。
func (workflow *workflow) VerifyArbitratedContent(ctx context.Context, command arbitratedContentCommand) (*arbitratedContentResult, error) {
	const op = "buyer.VerifyArbitratedContent"
	if err := workflow.requireSelf(op); err != nil {
		return nil, err
	}
	requestArtifact, err := wire.ParseAs(wire.ContentRetrievalRequest, command.RetrievalRequestRaw)
	if err != nil {
		return nil, err
	}
	responseArtifact, err := wire.ParseAs(wire.ContentRetrievalResponse, command.RetrievalResponseRaw)
	if err != nil {
		return nil, err
	}
	retrievalRequest, err := wire.DecodeContentRetrievalRequest(requestArtifact)
	if err != nil {
		return nil, err
	}
	retrievalResponse, err := wire.DecodeContentRetrievalResponse(responseArtifact)
	if err != nil {
		return nil, err
	}
	opening := command.Pool.Opening()
	previous := command.Pool.Payment()
	localAuthorization := command.Request.Request()
	if localAuthorization == nil {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 11, "request", "persisted authorization is required")
	}
	if err := ensureOwnership(workflow.publicKey[:], opening); err != nil {
		return nil, err
	}
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	requestTerms, quoteTerms, err := content.VerifyContentRequestEvidence(localAuthorization, command.Quote.Quote(), opening)
	if err != nil {
		return nil, err
	}
	refundTemplateTxID := pool.RefundTemplateTxID(bytes.Clone(requestTerms.RefundTemplateTxID))
	openingDetails, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, fmt.Errorf("derive pool opening details: %w", err)
	}
	if openingDetails.RefundTemplateTxID != refundTemplateTxID {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 11, "refund_template_txid", "content request is not bound to opening proof")
	}
	// 本地独立重建 expected Claim，精确校验自己发出的 Kind 10。
	built, err := arbitration.BuildClaimFromAuthorization(opening, localAuthorization)
	if err != nil {
		return nil, fmt.Errorf("rebuild expected arbitration Claim: %w", err)
	}
	localClaimID, _, err := arbitration.DecodeContentRetrievalRequestDocument(retrievalRequest.ContentRetrievalRequestCBOR)
	if err != nil {
		return nil, err
	}
	if localClaimID != built.ArbitrationClaimID {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 11, "arbitration_claim_id", "retrieval request does not reference the locally rebuilt claim")
	}
	if err := protocol.VerifyWireDocument(workflow.publicKey[:], protocol.WireVersion, 10, retrievalRequest.ContentRetrievalRequestCBOR, retrievalRequest.BuyerContentRetrievalRequestSignature); err != nil {
		return nil, protocol.Wrap(fmt.Errorf("buyer retrieval signature invalid: %v", err), op, protocol.CodeInvalidSignature, 11, "buyer_content_retrieval_request_signature")
	}
	result, err := arbitration.VerifyContentRetrievalResponse(retrievalRequest, opening.ArbiterPublicKey, retrievalResponse)
	if err != nil {
		return nil, err
	}
	outcome := &arbitratedContentResult{ContentRetrievalRequestID: result.ContentRetrievalRequestID, ArbitrationClaimID: built.ArbitrationClaimID, Available: result.Available, UnavailableReason: result.UnavailableReason}
	if !result.Available {
		return outcome, nil
	}
	contentHashes, err := content.DecodeContentHashes(requestTerms.ContentHashesCBOR)
	if err != nil {
		return nil, err
	}
	effectiveSeed, err := content.VerifyContentPayloads(ctx, quoteTerms, contentHashes, result.Payloads, append([]byte(nil), command.Seed...))
	if err != nil {
		return nil, err
	}
	price, err := content.ContentHashesPriceSatoshis(ctx, quoteTerms, contentHashes, effectiveSeed)
	if err != nil {
		return nil, err
	}
	// available 分支的连续性检查：序号恰好 +1、绝对累计金额恰好加本批价格。
	if previous == nil || previous.RefundTemplateTxID != refundTemplateTxID || previous.PaymentSequence+1 != requestTerms.PaymentSequence {
		return nil, staleSequenceErr(op)
	}
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	if previous.SellerAmountSatoshis > ^uint64(0)-price || requestTerms.SellerAmountAfterSatoshis != previous.SellerAmountSatoshis+price {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 11, "seller_amount_after_satoshis", "seller amount does not match aggregate content price")
	}
	outcome.Payloads = clonePayloads(result.Payloads)
	return outcome, nil
}

func clonePayloads(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = append([]byte(nil), values[index]...)
	}
	return result
}

func staleSequenceErr(op string) error {
	return protocol.Errorf(op, protocol.CodeStateConflict, 0, "payment_sequence", "stale payment sequence")
}
