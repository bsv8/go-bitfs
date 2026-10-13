package arbiter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

// workflow 是持有 Arbiter 签名能力的 007/008 角色编排。除固定的 Signer 公钥
// 外它不持有任何状态；没有持久化、网络、节点或时钟注入点。所有时间/高度
// 判断使用调用方显式传入的 Facts。
type workflow struct {
	signer    protocol.Signer
	publicKey protocol.PublicKey
}

// newWorkflow 固定并验证 Signer 公钥后返回角色编排。Signer 公钥在生命周期内
// 不得变化；后续任何签名返回都会针对该公钥自验。
func newWorkflow(signer protocol.Signer) (*workflow, error) {
	const op = "arbiter.newWorkflow"
	if signer == nil {
		return nil, protocol.Errorf(op, protocol.CodeSignerUnavailable, 0, "signer", "arbiter workflow requires a signer")
	}
	// 冻结公钥：后续所有下游签名/自验都对照构造时公钥，托管换钥即 invalid_signature。
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

// PrepareArbitration 对 exact Kind 8 托管请求做完整证据验证但绝不签名：
// Claim 结构、买方授权签名、卖方 Claim 签名、逐 payload 哈希、按显式正仲裁费
// 独立重建 candidate、Claim 归属本 Arbiter、交付截止未过（Facts.Now）、退款
// 模板尚未到期（只读取锁定类型对应的事实）。本步骤不签名也无长计算，因此不
// 接收 context。应用必须在调用 SignPreparedArbitration 之前先持久化 exact
// 托管证据（preparedArbitration.RequestCBOR、Claim ID、费用与 payload bundle）。
func (workflow *workflow) PrepareArbitration(facts protocol.Facts, rawKind8 []byte, fee protocol.Satoshis) (*preparedArbitration, error) {
	const op = "arbiter.PrepareArbitration"
	if workflow == nil || workflow.signer == nil {
		return nil, protocol.Errorf(op, protocol.CodeUnauthorized, 8, "workflow", "arbitration workflow is required")
	}
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
	claim, authorization, payloads, unsigned, claimID, authID, keys, err := arbitration.ValidateRequestEvidence(request, uint64(fee))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(keys.ArbiterPublicKey, workflow.publicKey[:]) {
		return nil, protocol.Errorf(op, protocol.CodeUnauthorized, 8, "arbiter_public_key", "Claim arbiter key does not match workflow key")
	}
	if !now.Before(unixSeconds(authorization.DeliveryDeadlineUnixSeconds)) {
		return nil, protocol.Errorf(op, protocol.CodeExpired, 8, "delivery_deadline_unix_seconds", "delivery deadline has passed")
	}
	claimLockTime, err := pool.RefundTemplateLockTime(claim.RefundTemplateRaw)
	if err != nil {
		return nil, err
	}
	// 退款门禁只读取锁定类型对应的事实；timestamp 锁定复用本次 Now。
	if err := facts.CheckRefundNotExpired(claimLockTime); err != nil {
		return nil, protocol.WrapClassified(fmt.Errorf("refund template is no longer available for arbitration: %w", err), op, 8, "refund_template_raw")
	}
	exactRequest, err := arbitration.MarshalRequest(request)
	if err != nil {
		return nil, err
	}
	return &preparedArbitration{
		request: request, claim: claim, unsigned: cloneUnsigned(unsigned), payloads: cloneByteSlices(payloads),
		arbitrationClaimID: claimID, paymentAuthorizationID: authID, arbiterAmountSatoshis: fee,
		arbiterPublicKey:    append([]byte(nil), keys.ArbiterPublicKey...),
		evidenceCommitment:  preparedEvidenceCommitment(exactRequest, claimID[:], uint64(fee), unsigned),
		deadlineUnixSeconds: authorization.DeliveryDeadlineUnixSeconds,
	}, nil
}

// SignPreparedArbitration 是先持久化后的签名步骤：从冻结的 exact Kind 8 字节
// 独立重建交易与 digest，重新比较 Claim ID、费用、角色、deadline（用本次
// 显式 Facts.Now）与 candidate，然后按固定顺序签名——先仲裁交易签名，再编码
// 回执，最后生成并自验统一回执消息签名。绝不信任缓存的 mutable candidate。
func (workflow *workflow) SignPreparedArbitration(ctx context.Context, facts protocol.Facts, prepared *preparedArbitration) (wire.Artifact, error) {
	const op = "arbiter.SignPreparedArbitration"
	if workflow == nil || workflow.signer == nil {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeUnauthorized, 9, "workflow", "arbitration workflow is required")
	}
	if ctx == nil {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeCanceled, 9, "ctx", "a non-nil context is required")
	}
	if prepared == nil || prepared.request == nil || prepared.claim == nil || prepared.unsigned == nil || len(prepared.arbitrationClaimID) != sha256.Size || prepared.arbiterAmountSatoshis == 0 {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 9, "prepared", "prepared arbitration is required")
	}
	if err := ctx.Err(); err != nil {
		return wire.Artifact{}, protocol.Wrap(err, op, protocol.CodeCanceled, 9, "")
	}
	now, err := facts.RequireNow()
	if err != nil {
		return wire.Artifact{}, err
	}
	if !now.Before(unixSeconds(prepared.deadlineUnixSeconds)) {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeExpired, 9, "delivery_deadline_unix_seconds", "delivery deadline passed before custody signing")
	}
	if !bytes.Equal(workflow.publicKey[:], prepared.arbiterPublicKey) {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeUnauthorized, 9, "arbiter_public_key", "prepared arbitration belongs to another arbiter")
	}
	// Everything below derives from the revalidated request bytes alone; the
	// cached Claim is never trusted for signing so tampering with any cached
	// structure cannot steer transaction construction.
	frozenFeeSatoshis := prepared.arbiterAmountSatoshis
	freshClaim, _, _, rebuilt, freshClaimID, freshAuthID, keys, err := arbitration.ValidateRequestEvidence(arbitration.CloneRequest(prepared.request), uint64(frozenFeeSatoshis))
	if err != nil {
		return wire.Artifact{}, err
	}
	if !bytes.Equal(keys.ArbiterPublicKey, workflow.publicKey[:]) {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeUnauthorized, 9, "arbiter_public_key", "Claim arbiter key does not match workflow key")
	}
	if freshClaimID != prepared.arbitrationClaimID || freshAuthID != prepared.paymentAuthorizationID {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeStateConflict, 9, "claim_id", "prepared arbitration evidence changed")
	}
	if rebuilt.ArbiterAmountSatoshis != uint64(frozenFeeSatoshis) || !equalUnsigned(rebuilt, prepared.unsigned) {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeStateConflict, 9, "unsigned_candidate", "prepared candidate changed")
	}
	// Prepare→Sign 间隙重检退款锁（timestamp/height 两种锁定都覆盖）：
	// 持久化或排队期间退款一旦成熟，退款交易与仲裁交易将竞态花费同一池
	// 输出。此门禁在任何 Signer 调用之前执行——被拒时 Signer 调用次数为 0，
	// 不产生任何部分签名。Restore 产物与本门禁同源。
	claimLockTime, err := pool.RefundTemplateLockTime(freshClaim.RefundTemplateRaw)
	if err != nil {
		return wire.Artifact{}, err
	}
	if err := facts.CheckRefundNotExpired(claimLockTime); err != nil {
		return wire.Artifact{}, protocol.WrapClassified(fmt.Errorf("refund gate between prepare and sign: %w", err), op, 9, "refund_template_raw")
	}
	exactRequest, err := arbitration.MarshalRequest(prepared.request)
	if err != nil {
		return wire.Artifact{}, err
	}
	if !bytes.Equal(preparedEvidenceCommitment(exactRequest, prepared.arbitrationClaimID[:], uint64(frozenFeeSatoshis), rebuilt), prepared.evidenceCommitment) {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeStateConflict, 9, "evidence_commitment", "prepared evidence commitment changed")
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(freshClaim.PoolOutputLockingScript)
	if err != nil {
		return wire.Artifact{}, err
	}
	// 先生成并自验仲裁交易签名，再编码回执，最后生成并自验回执统一消息签名。
	arbiterTransactionSignature, err := engine.SignArbitrationArbiterPayment(ctx, rebuilt, workflow.signer)
	if err != nil {
		return wire.Artifact{}, fmt.Errorf("sign arbitration transaction: %w", err)
	}
	if err := engine.VerifyArbitrationArbiterPayment(rebuilt, arbiterTransactionSignature); err != nil {
		return wire.Artifact{}, fmt.Errorf("verify arbitration transaction signature: %w", err)
	}
	receipt := &arbitration.ArbitrationReceipt{
		ArbitrationClaimID:                 prepared.arbitrationClaimID,
		ArbiterAmountSatoshis:              uint64(frozenFeeSatoshis),
		ArbiterPaymentTransactionSignature: append([]byte(nil), arbiterTransactionSignature...),
	}
	receiptCBOR, err := arbitration.MarshalReceipt(receipt)
	if err != nil {
		return wire.Artifact{}, err
	}
	receiptSignature, err := protocol.SignWireDocument(ctx, workflow.signer, protocol.WireVersion, 9, receiptCBOR)
	if err != nil {
		return wire.Artifact{}, fmt.Errorf("sign arbitration receipt: %w", err)
	}
	if err := protocol.VerifyWireDocument(workflow.publicKey[:], protocol.WireVersion, 9, receiptCBOR, receiptSignature); err != nil {
		return wire.Artifact{}, fmt.Errorf("verify arbitration receipt signature: %w", err)
	}
	response := &arbitration.ArbitrationResponse{ArbitrationReceiptCBOR: receiptCBOR, ArbiterArbitrationReceiptSignature: receiptSignature}
	if _, err := arbitration.MarshalResponse(response); err != nil {
		return wire.Artifact{}, err
	}
	return wire.EncodeArbitrationResponse(response)
}

// AuthenticateRetrieval 仅完成 Buyer 鉴权，用于 not_ready / gone 分支：
// 时间无关，不需要 Kind 9 存在。rawKind10 与 storedKind8 都是 exact bytes；
// 鉴权失败返回 invalid_signature/unauthorized/invalid_evidence 分类错误。
func (workflow *workflow) AuthenticateRetrieval(rawKind10 []byte, storedKind8 []byte) error {
	const op = "arbiter.AuthenticateRetrieval"
	if workflow == nil || workflow.signer == nil {
		return protocol.Errorf(op, protocol.CodeUnauthorized, 10, "workflow", "arbitration workflow is required")
	}
	retrievalRequest, err := arbitration.UnmarshalContentRetrievalRequest(rawKind10)
	if err != nil {
		return err
	}
	storedRequest, err := arbitration.UnmarshalRequest(storedKind8)
	if err != nil {
		return err
	}
	return arbitration.AuthenticateContentRetrievalRequest(retrievalRequest, storedRequest, workflow.publicKey[:])
}

// VerifyRetrievableCustody 对完整托管证据（exact Kind 8 + exact Kind 9）做
// 时间无关全量验证，再鉴权 exact Kind 10，最后返回 verified custody/payload。
// 过期的 deadline 或已到期的退款锁定不会拒绝仍在保留窗口内的已签托管证据。
func (workflow *workflow) VerifyRetrievableCustody(rawKind10 []byte, storedKind8 []byte, storedKind9 []byte) (*arbitration.VerifiedCustodiedContent, error) {
	const op = "arbiter.VerifyRetrievableCustody"
	if workflow == nil || workflow.signer == nil {
		return nil, protocol.Errorf(op, protocol.CodeUnauthorized, 0, "workflow", "arbitration workflow is required")
	}
	storedRequest, err := arbitration.UnmarshalRequest(storedKind8)
	if err != nil {
		return nil, err
	}
	storedResponse, err := arbitration.UnmarshalResponse(storedKind9)
	if err != nil {
		return nil, err
	}
	verified, err := arbitration.VerifyCustodiedContent(storedRequest, storedResponse)
	if err != nil {
		return nil, err
	}
	retrievalRequest, err := arbitration.UnmarshalContentRetrievalRequest(rawKind10)
	if err != nil {
		return nil, err
	}
	if err := arbitration.AuthenticateContentRetrievalRequest(retrievalRequest, verified.Request, workflow.publicKey[:]); err != nil {
		return nil, err
	}
	return verified, nil
}

// BuildUnavailableRetrieval 构造并签署 valid Kind 11 unavailable Artifact：
// 只携带结构合法的 request ID 与诚实 reason，无 Claim、无角色公钥、无记录元数据。
func (workflow *workflow) BuildUnavailableRetrieval(ctx context.Context, requestID protocol.ContentRetrievalRequestID, reason arbitration.ContentRetrievalUnavailableReason) (wire.Artifact, error) {
	const op = "arbiter.BuildUnavailableRetrieval"
	if ctx == nil {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeCanceled, 11, "ctx", "a non-nil context is required")
	}
	if workflow == nil || workflow.signer == nil {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeUnauthorized, 11, "workflow", "arbitration workflow is required")
	}
	response, err := arbitration.BuildContentRetrievalUnavailable(ctx, requestID, reason, workflow.signer)
	if err != nil {
		return wire.Artifact{}, err
	}
	return wire.EncodeContentRetrievalResponse(response)
}

// BuildAvailableRetrieval 构造并签署 valid Kind 11 available Artifact，直接
// 附带经 content_payloads_id 绑定的 verified exact payloads。available 分支
// 不产生也不携带任何付款凭证。
func (workflow *workflow) BuildAvailableRetrieval(ctx context.Context, requestID protocol.ContentRetrievalRequestID, verifiedCustody *arbitration.VerifiedCustodiedContent) (wire.Artifact, error) {
	const op = "arbiter.BuildAvailableRetrieval"
	if ctx == nil {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeCanceled, 11, "ctx", "a non-nil context is required")
	}
	if workflow == nil || workflow.signer == nil {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeUnauthorized, 11, "workflow", "arbitration workflow is required")
	}
	if verifiedCustody == nil || len(verifiedCustody.PayloadsCBOR) == 0 {
		return wire.Artifact{}, protocol.Errorf(op, protocol.CodeInvalidEvidence, 11, "verified_custody", "verified custody with its exact payload bundle is required")
	}
	response, err := arbitration.BuildContentRetrievalAvailableRaw(ctx, requestID, verifiedCustody.PayloadsCBOR, workflow.signer)
	if err != nil {
		return wire.Artifact{}, err
	}
	return wire.EncodeContentRetrievalResponse(response)
}

// unixSeconds 把协议 UTC Unix 秒还原为 UTC time.Time（纯函数，无时钟读取）。
func unixSeconds(value int64) time.Time { return time.Unix(value, 0).UTC() }
