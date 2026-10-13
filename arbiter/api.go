package arbiter

// 本文件是 Arbiter 的纯函数边界：Prepare 阶段只做完整证据验证并返回普通证据包，
// 不持有任何不透明令牌；Sign 阶段从普通证据包重新验证全部证据后才调用 Signer。
// 安全性由每个步骤从原始证据全量重验保证，而不是由对象不可构造保证。SDK 不持有
// 跨步骤对象、不保存进度、不读取时钟、不访问存储，也不广播任何交易。

import (
	"bytes"
	"context"
	"fmt"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

// PreparedArbitrationEvidence 是已完整验证但尚未签名的普通仲裁证据包：
// exact Kind 8、按显式正费用独立重建的 candidate、Claim ID 与冻结费用。
// 应用可直接序列化持久化；SignPreparedArbitration 必须从它重新验证全部证据。
type PreparedArbitrationEvidence struct {
	// RawKind8 是卖方发来的 exact Kind 8 托管请求字节。
	RawKind8 []byte
	// CandidateRaw 是从 Claim primitives 按显式费用唯一重建的未签名仲裁交易原文。
	CandidateRaw []byte
	// ArbitrationClaimID = SHA-256(exact arbitration_claim_cbor)，托管记录身份。
	ArbitrationClaimID protocol.ArbitrationClaimID
	// FeeSatoshis 是本次仲裁的绝对仲裁费（正数，聪）。
	FeeSatoshis protocol.Satoshis
}

// SignedArbitrationEvidence 是签名阶段产出的普通证据包：冻结的 Prepare 证据、
// 待发送 exact Kind 9 与仲裁交易签名。CompleteArbitratedPayment 需要它来合并
// Seller/Arbiter 双签名。
type SignedArbitrationEvidence struct {
	// Prepared 是签名前的完整证据快照；合并时会再次全量重验。
	Prepared PreparedArbitrationEvidence
	// Outbound 是待发送 exact Kind 9 回执 Artifact。
	Outbound wire.Artifact
	// ArbiterTransactionSignature 是仲裁方对 candidate 的 detached 交易签名。
	ArbiterTransactionSignature []byte
}

// PrepareArbitration 对 exact Kind 8 托管请求做完整时间相关证据验证但绝不签名：
// Claim 结构、买方授权签名、卖方 Claim 签名、逐 payload 哈希、按显式正仲裁费
// 独立重建 candidate、交付截止未过（Facts.Now）、退款模板尚未到期（只读取锁定
// 类型对应的事实）。本步骤不签名也无长计算，因此不接收 context。应用必须在调用
// SignPreparedArbitration 之前先持久化返回的证据包。
func PrepareArbitration(facts protocol.Facts, rawKind8 []byte, fee protocol.Satoshis) (*PreparedArbitrationEvidence, error) {
	const op = "arbiter.PrepareArbitration"
	if fee == 0 {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 8, "fee_satoshis", "successful arbitration requires a positive arbiter amount")
	}
	request, err := arbitration.UnmarshalRequest(rawKind8)
	if err != nil {
		return nil, err
	}
	now, err := facts.RequireNow()
	if err != nil {
		return nil, err
	}
	claim, authorization, _, unsigned, claimID, _, _, err := arbitration.ValidateRequestEvidence(request, uint64(fee))
	if err != nil {
		return nil, err
	}
	if !now.Before(unixSeconds(authorization.DeliveryDeadlineUnixSeconds)) {
		return nil, protocol.Errorf(op, protocol.CodeExpired, 8, "delivery_deadline_unix_seconds", "delivery deadline has passed")
	}
	claimLockTime, err := pool.RefundTemplateLockTime(claim.RefundTemplateRaw)
	if err != nil {
		return nil, err
	}
	if err := facts.CheckRefundNotExpired(claimLockTime); err != nil {
		return nil, protocol.WrapClassified(fmt.Errorf("refund template is no longer available for arbitration: %w", err), op, 8, "refund_template_raw")
	}
	return &PreparedArbitrationEvidence{
		RawKind8:           bytes.Clone(rawKind8),
		CandidateRaw:       bytes.Clone(unsigned.RawTx),
		ArbitrationClaimID: claimID,
		FeeSatoshis:        fee,
	}, nil
}

// SignPreparedArbitration 是先持久化后的签名步骤：从冻结的 exact Kind 8 字节
// 独立重建交易与 digest，重新比较 Claim ID、费用、角色、deadline（用本次显式
// Facts.Now）与 candidate，然后按固定顺序签名——先仲裁交易签名，再编码回执，
// 最后生成并自验统一回执消息签名。绝不信任缓存的 mutable candidate。
func SignPreparedArbitration(ctx context.Context, facts protocol.Facts, prepared PreparedArbitrationEvidence, signer protocol.Signer) (*SignedArbitrationEvidence, error) {
	const op = "arbiter.SignPreparedArbitration"
	internal, err := restorePreparedArbitration(prepared.RawKind8, prepared.FeeSatoshis)
	if err != nil {
		return nil, err
	}
	if internal.arbitrationClaimID != prepared.ArbitrationClaimID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 9, "claim_id", "prepared claim ID does not match the revalidated evidence")
	}
	if !bytes.Equal(internal.unsigned.RawTx, prepared.CandidateRaw) {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 9, "unsigned_candidate", "prepared candidate does not match the independently rebuilt transaction")
	}
	workflow, err := newWorkflow(signer)
	if err != nil {
		return nil, err
	}
	outbound, err := workflow.SignPreparedArbitration(ctx, facts, internal)
	if err != nil {
		return nil, err
	}
	artifact, err := wire.ParseAs(wire.ArbitrationResponse, outbound.Bytes())
	if err != nil {
		return nil, err
	}
	response, err := wire.DecodeArbitrationResponse(artifact)
	if err != nil {
		return nil, err
	}
	receipt, err := arbitration.UnmarshalReceipt(response.ArbitrationReceiptCBOR)
	if err != nil {
		return nil, err
	}
	return &SignedArbitrationEvidence{
		Prepared:                    clonePreparedEvidence(prepared),
		Outbound:                    outbound,
		ArbiterTransactionSignature: bytes.Clone(receipt.ArbiterPaymentTransactionSignature),
	}, nil
}

// AuthenticateRetrieval 仅完成 Buyer 鉴权：时间无关，不需要 Kind 9 存在。
// rawKind10 与 storedKind8 都是 exact bytes；鉴权失败返回
// invalid_signature/unauthorized/invalid_evidence 分类错误。持有 storedKind8
// 记录的一方即托管仲裁方，因此本入口不需要再传仲裁方公钥。
func AuthenticateRetrieval(rawKind10 []byte, storedKind8 []byte) error {
	retrievalRequest, err := arbitration.UnmarshalContentRetrievalRequest(rawKind10)
	if err != nil {
		return err
	}
	storedRequest, err := arbitration.UnmarshalRequest(storedKind8)
	if err != nil {
		return err
	}
	claim, err := arbitration.UnmarshalClaim(storedRequest.ArbitrationClaimCBOR)
	if err != nil {
		return err
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return err
	}
	return arbitration.AuthenticateContentRetrievalRequest(retrievalRequest, storedRequest, keys.ArbiterPublicKey)
}

// BuildUnavailableRetrieval 构造并签署 valid exact Kind 11 unavailable Artifact：
// 只携带结构合法的 request ID 与诚实 reason，无 Claim、无角色公钥、无记录元数据。
func BuildUnavailableRetrieval(ctx context.Context, requestID protocol.ContentRetrievalRequestID, reason arbitration.ContentRetrievalUnavailableReason, signer protocol.Signer) (wire.Artifact, error) {
	const op = "arbiter.BuildUnavailableRetrieval"
	if ctx == nil {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeCanceled, 11, "ctx", "a non-nil context is required")
	}
	if signer == nil {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeSignerUnavailable, 11, "signer", "arbiter signer is required")
	}
	response, err := arbitration.BuildContentRetrievalUnavailable(ctx, requestID, reason, signer)
	if err != nil {
		return wire.Artifact{}, err
	}
	return wire.EncodeContentRetrievalResponse(response)
}

// BuildAvailableRetrieval 构造并签署 valid exact Kind 11 available Artifact，直接
// 附带经 content_payloads_id 绑定的 verified exact payloads。available 分支
// 不产生也不携带任何付款凭证。
func BuildAvailableRetrieval(ctx context.Context, requestID protocol.ContentRetrievalRequestID, custody *arbitration.VerifiedCustodiedContent, signer protocol.Signer) (wire.Artifact, error) {
	const op = "arbiter.BuildAvailableRetrieval"
	if ctx == nil {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeCanceled, 11, "ctx", "a non-nil context is required")
	}
	if signer == nil {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeSignerUnavailable, 11, "signer", "arbiter signer is required")
	}
	if custody == nil || len(custody.PayloadsCBOR) == 0 {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 11, "verified_custody", "verified custody with its exact payload bundle is required")
	}
	response, err := arbitration.BuildContentRetrievalAvailableRaw(ctx, requestID, custody.PayloadsCBOR, signer)
	if err != nil {
		return wire.Artifact{}, err
	}
	return wire.EncodeContentRetrievalResponse(response)
}

// CompleteArbitratedPayment 从签名证据包重建 paid candidate 并合并 Seller/Arbiter
// 双签名：重建、回执重验与双签名验证全部在 pool 内部一次完成；返回完整仲裁交易
// 原文，是否广播由应用决定。调用方提供卖方对同一 candidate 的 detached 交易签名。
func CompleteArbitratedPayment(signed SignedArbitrationEvidence, sellerSignature []byte) ([]byte, error) {
	const op = "arbiter.CompleteArbitratedPayment"
	request, err := arbitration.UnmarshalRequest(signed.Prepared.RawKind8)
	if err != nil {
		return nil, err
	}
	_, _, _, unsigned, claimID, _, keys, err := arbitration.ValidateRequestEvidence(request, uint64(signed.Prepared.FeeSatoshis))
	if err != nil {
		return nil, err
	}
	if claimID != signed.Prepared.ArbitrationClaimID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 9, "claim_id", "signed evidence claim ID does not match the revalidated claim")
	}
	if !bytes.Equal(unsigned.RawTx, signed.Prepared.CandidateRaw) {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 9, "unsigned_candidate", "signed evidence candidate does not match the independently rebuilt transaction")
	}
	artifact, err := wire.ParseAs(wire.ArbitrationResponse, signed.Outbound.Bytes())
	if err != nil {
		return nil, err
	}
	response, err := wire.DecodeArbitrationResponse(artifact)
	if err != nil {
		return nil, err
	}
	receipt, err := arbitration.UnmarshalReceipt(response.ArbitrationReceiptCBOR)
	if err != nil {
		return nil, err
	}
	if receipt.ArbitrationClaimID != signed.Prepared.ArbitrationClaimID {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 9, "arbitration_claim_id", "receipt Claim ID does not match the signed evidence")
	}
	if !bytes.Equal(receipt.ArbiterPaymentTransactionSignature, signed.ArbiterTransactionSignature) {
		return nil, protocol.Errorf(op, protocol.CodeStateConflict, 9, "arbiter_payment_transaction_signature", "receipt transaction signature does not match the signed evidence")
	}
	if err := protocol.VerifyWireDocument(keys.ArbiterPublicKey, protocol.WireVersion, 9, response.ArbitrationReceiptCBOR, response.ArbiterArbitrationReceiptSignature); err != nil {
		return nil, protocol.Wrap(fmt.Errorf("arbitration receipt signature is invalid: %v", err), op, protocol.CodeInvalidSignature, 9, "arbiter_arbitration_receipt_signature")
	}
	verified, err := pool.CompleteArbitratedTransaction(unsigned, sellerSignature, signed.ArbiterTransactionSignature)
	if err != nil {
		return nil, err
	}
	return verified.RawTx(), nil
}

// clonePreparedEvidence 深拷贝 Prepare 证据包，保证返回结果与调用方输入解耦。
func clonePreparedEvidence(evidence PreparedArbitrationEvidence) PreparedArbitrationEvidence {
	return PreparedArbitrationEvidence{
		RawKind8:           bytes.Clone(evidence.RawKind8),
		CandidateRaw:       bytes.Clone(evidence.CandidateRaw),
		ArbitrationClaimID: evidence.ArbitrationClaimID,
		FeeSatoshis:        evidence.FeeSatoshis,
	}
}
