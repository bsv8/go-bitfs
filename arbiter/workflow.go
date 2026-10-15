package arbiter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

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

// SignPreparedArbitration 是先持久化后的签名步骤：从冻结的 exact Kind 8 字节
// 独立重建交易与 digest，重新比较 Claim ID、费用、角色
// 与 candidate，然后按固定顺序签名——先仲裁交易签名，再编码
// 回执，最后生成并自验统一回执消息签名。绝不信任缓存的 mutable candidate。
func (workflow *workflow) SignPreparedArbitration(ctx context.Context, prepared *preparedArbitration) (wire.Artifact, error) {
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
	// 离线仲裁只验证证据与费用。退款已可执行不使证据失效；链上花费竞争由
	// 交易广播方承担，仲裁方不伪造高度也不查询 UTXO。
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
