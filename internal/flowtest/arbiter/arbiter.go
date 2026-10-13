// Package arbiter 是内部测试兼容适配器：把仲裁方纯函数 API 包装成旧的“持有
// Signer 的 workflow”形状，仅用于让既有安全测试继续以新实现为唯一底层执行。
// 它不是 SDK 公开面，也不进入发布文档。
package arbiter

import (
	"bytes"
	"context"

	realarbiter "github.com/bsv8/go-bitfs/arbiter"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
)

// Workflow 是测试用仲裁方会话：只固定 Signer 与公钥。
type Workflow struct {
	signer    protocol.Signer
	publicKey protocol.PublicKey
}

// NewWorkflow 固定并验证 Signer 公钥。
func NewWorkflow(signer protocol.Signer) (*Workflow, error) {
	if signer == nil {
		return nil, protocol.Errorf("arbiter.NewWorkflow", protocol.CodeSignerUnavailable, 0, "signer", "arbiter workflow requires a signer")
	}
	bound, err := protocol.BindSigner(signer)
	if err != nil {
		return nil, protocol.Wrap(err, "arbiter.NewWorkflow", protocol.CodeInvalidEvidence, 0, "signer")
	}
	return &Workflow{signer: bound, publicKey: bound.PublicKey()}, nil
}

// PublicKey 返回固定压缩公钥副本。
func (w *Workflow) PublicKey() []byte { return append([]byte(nil), w.publicKey[:]...) }

// PreparedArbitration 是旧形状的普通证据包视图：所有 getter 都从 exact Kind 8
// 重新解码，返回深拷贝，篡改 getter 结果无法影响签署。
type PreparedArbitration struct {
	evidence  realarbiter.PreparedArbitrationEvidence
	publicKey []byte
}

// Request 返回深拷贝的 exact Kind 8 解码结果。
func (p *PreparedArbitration) Request() *arbitration.ArbitrationRequest {
	if p == nil {
		return nil
	}
	artifact, err := wire.ParseAs(wire.ArbitrationRequest, p.evidence.RawKind8)
	if err != nil {
		return nil
	}
	request, err := wire.DecodeArbitrationRequest(artifact)
	if err != nil {
		return nil
	}
	return request
}

// RequestCBOR 返回 exact Claim CBOR。
func (p *PreparedArbitration) RequestCBOR() ([]byte, error) {
	request := p.Request()
	if request == nil {
		return nil, protocol.Errorf("arbiter.PreparedArbitration.RequestCBOR", protocol.CodeInvalidEvidence, 8, "request", "prepared arbitration is empty")
	}
	return append([]byte(nil), request.ArbitrationClaimCBOR...), nil
}

// Claim 返回深拷贝的 Claim 解码结果。
func (p *PreparedArbitration) Claim() *arbitration.ArbitrationClaim {
	request := p.Request()
	if request == nil {
		return nil
	}
	claim, err := arbitration.UnmarshalClaim(request.ArbitrationClaimCBOR)
	if err != nil {
		return nil
	}
	return claim
}

// RefundTemplateTxID 从 Claim 退款模板派生费用池关联 ID 字节。
func (p *PreparedArbitration) RefundTemplateTxID() []byte {
	claim := p.Claim()
	if claim == nil {
		return nil
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil
	}
	id, err := engine.TransactionID(claim.RefundTemplateRaw)
	if err != nil {
		return nil
	}
	return append([]byte(nil), id[:]...)
}

// ArbitrationClaimID 返回 Claim ID。
func (p *PreparedArbitration) ArbitrationClaimID() protocol.ArbitrationClaimID {
	if p == nil {
		return protocol.ArbitrationClaimID{}
	}
	return p.evidence.ArbitrationClaimID
}

// PaymentAuthorizationID 返回 Claim 内授权的 typed ID。
func (p *PreparedArbitration) PaymentAuthorizationID() protocol.PaymentAuthorizationID {
	claim := p.Claim()
	if claim == nil {
		return protocol.PaymentAuthorizationID{}
	}
	id, err := content.PaymentAuthorizationID(claim.PaymentAuthorizationCBOR)
	if err != nil {
		return protocol.PaymentAuthorizationID{}
	}
	return id
}

// FeeSatoshis 返回冻结仲裁费。
func (p *PreparedArbitration) FeeSatoshis() protocol.Satoshis {
	if p == nil {
		return 0
	}
	return p.evidence.FeeSatoshis
}

// ContentPayloadsCBOR 返回 exact payload attachment 字节副本。
func (p *PreparedArbitration) ContentPayloadsCBOR() []byte {
	request := p.Request()
	if request == nil {
		return nil
	}
	return append([]byte(nil), request.ContentPayloadsCBOR...)
}

// ContentPayloads 返回解码后的 payload 批次。
func (p *PreparedArbitration) ContentPayloads() [][]byte {
	payloads, err := content.DecodeContentPayloads(p.ContentPayloadsCBOR())
	if err != nil {
		return nil
	}
	return payloads
}

// DeadlineUnixSeconds 返回买方授权的交付截止时间。
func (p *PreparedArbitration) DeadlineUnixSeconds() content.UnixSeconds {
	claim := p.Claim()
	if claim == nil {
		return 0
	}
	authorization, err := content.DecodePaymentAuthorization(claim.PaymentAuthorizationCBOR)
	if err != nil {
		return 0
	}
	return content.UnixSeconds(authorization.DeliveryDeadlineUnixSeconds)
}

// ArbiterPublicKey 返回 Claim 锁定的仲裁方压缩公钥副本。
func (p *PreparedArbitration) ArbiterPublicKey() []byte {
	claim := p.Claim()
	if claim == nil {
		return nil
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil
	}
	return append([]byte(nil), keys.ArbiterPublicKey...)
}

// PreparedBelongsTo 报告该证据是否归属指定仲裁方公钥。
func (p *PreparedArbitration) PreparedBelongsTo(publicKey []byte) bool {
	return p != nil && bytes.Equal(p.publicKey, publicKey)
}

// PrepareArbitration 完整验证 exact Kind 8 并返回可持久化的普通证据包。
func (w *Workflow) PrepareArbitration(facts protocol.Facts, rawKind8 []byte, fee protocol.Satoshis) (*PreparedArbitration, error) {
	evidence, err := realarbiter.PrepareArbitration(facts, rawKind8, fee)
	if err != nil {
		return nil, err
	}
	prepared := &PreparedArbitration{evidence: *evidence, publicKey: append([]byte(nil), w.publicKey[:]...)}
	if !bytes.Equal(prepared.ArbiterPublicKey(), w.publicKey[:]) {
		return nil, protocol.Errorf("arbiter.PrepareArbitration", protocol.CodeUnauthorized, 8, "arbiter_public_key", "Claim arbiter key does not match workflow key")
	}
	return prepared, nil
}

// SignPreparedArbitration 从普通证据包重新验证全部证据后签名。
func (w *Workflow) SignPreparedArbitration(ctx context.Context, facts protocol.Facts, prepared *PreparedArbitration) (wire.Artifact, error) {
	if prepared == nil {
		return wire.Artifact{}, protocol.Errorf("arbiter.SignPreparedArbitration", protocol.CodeInvalidEvidence, 9, "prepared", "prepared arbitration is required")
	}
	signed, err := realarbiter.SignPreparedArbitration(ctx, facts, prepared.evidence, w.signer)
	if err != nil {
		return wire.Artifact{}, err
	}
	return signed.Outbound, nil
}

// RestorePreparedArbitration 从 exact Kind 8 + 冻结费用恢复普通证据包；不读取
// 任何时间事实（Prepare 时已执行门禁，Sign 会用新 Facts 重查）。
func RestorePreparedArbitration(rawKind8 []byte, fee protocol.Satoshis) (*PreparedArbitration, error) {
	if fee == 0 {
		return nil, protocol.Errorf("arbiter.RestorePreparedArbitration", protocol.CodeInvalidEvidence, 8, "fee_satoshis", "frozen arbitration fee must be positive")
	}
	request, err := arbitration.UnmarshalRequest(rawKind8)
	if err != nil {
		return nil, err
	}
	_, _, _, unsigned, claimID, _, keys, err := arbitration.ValidateRequestEvidence(request, uint64(fee))
	if err != nil {
		return nil, err
	}
	return &PreparedArbitration{
		evidence:  realarbiter.PreparedArbitrationEvidence{RawKind8: bytes.Clone(rawKind8), CandidateRaw: bytes.Clone(unsigned.RawTx), ArbitrationClaimID: claimID, FeeSatoshis: fee},
		publicKey: append([]byte(nil), keys.ArbiterPublicKey...),
	}, nil
}

// AuthenticateRetrieval 完成 Kind 10 的买方鉴权。
func (w *Workflow) AuthenticateRetrieval(rawKind10 []byte, storedKind8 []byte) error {
	if err := realarbiter.AuthenticateRetrieval(rawKind10, storedKind8); err != nil {
		return err
	}
	request, err := arbitration.UnmarshalRequest(storedKind8)
	if err != nil {
		return err
	}
	claim, err := arbitration.UnmarshalClaim(request.ArbitrationClaimCBOR)
	if err != nil {
		return err
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return err
	}
	if !bytes.Equal(keys.ArbiterPublicKey, w.publicKey[:]) {
		return protocol.Errorf("arbiter.AuthenticateRetrieval", protocol.CodeUnauthorized, 10, "arbiter_public_key", "custody Claim names another arbiter")
	}
	return nil
}

// VerifyRetrievableCustody 对 exact Kind 8/9 全量验证后鉴权 exact Kind 10。
func (w *Workflow) VerifyRetrievableCustody(rawKind10 []byte, storedKind8 []byte, storedKind9 []byte) (*arbitration.VerifiedCustodiedContent, error) {
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
	if err := w.AuthenticateRetrieval(rawKind10, storedKind8); err != nil {
		return nil, err
	}
	return verified, nil
}

// BuildUnavailableRetrieval 构造并签署 exact Kind 11 unavailable。
func (w *Workflow) BuildUnavailableRetrieval(ctx context.Context, requestID protocol.ContentRetrievalRequestID, reason arbitration.ContentRetrievalUnavailableReason) (wire.Artifact, error) {
	return realarbiter.BuildUnavailableRetrieval(ctx, requestID, reason, w.signer)
}

// BuildAvailableRetrieval 构造并签署 exact Kind 11 available。
func (w *Workflow) BuildAvailableRetrieval(ctx context.Context, requestID protocol.ContentRetrievalRequestID, custody *arbitration.VerifiedCustodiedContent) (wire.Artifact, error) {
	return realarbiter.BuildAvailableRetrieval(ctx, requestID, custody, w.signer)
}

// CompleteArbitratedPayment 合并卖方签名并返回完整仲裁交易。
func (w *Workflow) CompleteArbitratedPayment(signed *realarbiter.SignedArbitrationEvidence, sellerSignature []byte) ([]byte, error) {
	if signed == nil {
		return nil, protocol.Errorf("arbiter.CompleteArbitratedPayment", protocol.CodeInvalidEvidence, 9, "signed", "signed arbitration evidence is required")
	}
	return realarbiter.CompleteArbitratedPayment(*signed, sellerSignature)
}
