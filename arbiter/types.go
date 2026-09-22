// Package arbiter 是 007/008 的 Arbiter 角色 API：持有固定受约束 Signer，
// 完成"先完整验证并持久化托管证据、再独立重建交易与 digest 后签名"的
// Prepare-before-Sign 编排，以及时间无关的 008 取回鉴权/托管验证与 Kind 11
// 两分支构造。它不拥有存储、网络、节点或业务最新状态；应用负责在
// Prepare 与 Sign 之间先持久化 exact 托管证据。
package arbiter

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/content"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/protocol"
)

// preparedArbitration 是 PrepareArbitration 的不透明结果：完整验证通过但尚未
// 签名的托管证据。所有导出访问都经防御性复制 getter，调用方可以安全地把证据
// 持久化，却拿不到可变引用去篡改签名输入。它不是 wire 报文，也不携带任何
// WireVersion 字段；跨进程恢复必须走 restorePreparedArbitration 从 exact bytes
// 全量重验。
type preparedArbitration struct {
	request                *arbitration.ArbitrationRequest
	claim                  *arbitration.ArbitrationClaim
	unsigned               *pool.UnsignedPayment
	payloads               [][]byte
	arbitrationClaimID     protocol.ArbitrationClaimID
	paymentAuthorizationID protocol.PaymentAuthorizationID
	arbiterAmountSatoshis  protocol.Satoshis
	arbiterPublicKey       []byte
	evidenceCommitment     []byte
	deadlineUnixSeconds    int64
}

// Request 返回深拷贝的 exact Kind 8 托管请求（含 Claim、卖方签名与 payload
// attachment）。应用必须先持久化它的 canonical 编码再调用 SignPreparedArbitration。
func (prepared *preparedArbitration) Request() *arbitration.ArbitrationRequest {
	if prepared == nil {
		return nil
	}
	return arbitration.CloneRequest(prepared.request)
}

// RequestCBOR 返回 exact Kind 8 的 canonical wire 字节；发送与持久化都用它。
// （PreparedAt 之类的观测元数据由应用连同其 Facts 来源自行保存，不属于可
// 验证协议证据，因此不在本值上。）
func (prepared *preparedArbitration) RequestCBOR() ([]byte, error) {
	if prepared == nil || prepared.request == nil {
		return nil, protocol.Errorf("arbiter.preparedArbitration.RequestCBOR", protocol.CodeInvalidEvidence, 8, "request", "prepared arbitration is empty")
	}
	return arbitration.MarshalRequest(prepared.request)
}

// Claim 返回深拷贝的已解码 Claim 证据。
func (prepared *preparedArbitration) Claim() *arbitration.ArbitrationClaim {
	if prepared == nil {
		return nil
	}
	return cloneClaim(prepared.claim)
}

// RefundTemplateTxID 返回从退款模板派生的费用池统一关联 ID 副本。
func (prepared *preparedArbitration) RefundTemplateTxID() []byte {
	if prepared == nil || prepared.unsigned == nil {
		return nil
	}
	return append([]byte(nil), prepared.unsigned.RefundTemplateTxID[:]...)
}

// ArbitrationClaimID 返回 SHA-256(exact_claim_cbor)，Kind 8 文档 typed ID。
func (prepared *preparedArbitration) ArbitrationClaimID() protocol.ArbitrationClaimID {
	if prepared == nil {
		return protocol.ArbitrationClaimID{}
	}
	return prepared.arbitrationClaimID
}

// PaymentAuthorizationID 返回被托管付款授权的 SHA-256 typed ID。
func (prepared *preparedArbitration) PaymentAuthorizationID() protocol.PaymentAuthorizationID {
	if prepared == nil {
		return protocol.PaymentAuthorizationID{}
	}
	return prepared.paymentAuthorizationID
}

// FeeSatoshis 返回冻结的绝对仲裁费（output[2] 金额）；成功路径恒为正数。
func (prepared *preparedArbitration) FeeSatoshis() protocol.Satoshis {
	if prepared == nil {
		return 0
	}
	return prepared.arbiterAmountSatoshis
}

// ContentPayloadsCBOR 返回 exact content_payloads_cbor attachment 字节副本。
func (prepared *preparedArbitration) ContentPayloadsCBOR() []byte {
	if prepared == nil || prepared.request == nil {
		return nil
	}
	return append([]byte(nil), prepared.request.ContentPayloadsCBOR...)
}

// ContentPayloads 返回按授权顺序深拷贝的 payload 内容。
func (prepared *preparedArbitration) ContentPayloads() [][]byte {
	if prepared == nil {
		return nil
	}
	return cloneByteSlices(prepared.payloads)
}

// DeadlineUnixSeconds 返回买方授权携带的交付截止时间（UTC Unix 秒）；是否
// 已经过期由调用方用自己的显式事实判断。
func (prepared *preparedArbitration) DeadlineUnixSeconds() content.UnixSeconds {
	if prepared == nil {
		return 0
	}
	return content.UnixSeconds(prepared.deadlineUnixSeconds)
}

// ArbiterPublicKey 返回 Claim 锁定脚本中恢复的仲裁方压缩公钥副本。
func (prepared *preparedArbitration) ArbiterPublicKey() []byte {
	if prepared == nil {
		return nil
	}
	return append([]byte(nil), prepared.arbiterPublicKey...)
}

func cloneClaim(claim *arbitration.ArbitrationClaim) *arbitration.ArbitrationClaim {
	if claim == nil {
		return nil
	}
	cloned := *claim
	cloned.PoolOutputLockingScript = append([]byte(nil), claim.PoolOutputLockingScript...)
	cloned.RefundTemplateRaw = append([]byte(nil), claim.RefundTemplateRaw...)
	cloned.PaymentAuthorizationCBOR = append([]byte(nil), claim.PaymentAuthorizationCBOR...)
	cloned.BuyerPaymentAuthorizationSignature = append([]byte(nil), claim.BuyerPaymentAuthorizationSignature...)
	return &cloned
}

func cloneByteSlices(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = append([]byte(nil), values[index]...)
	}
	return result
}

// preparedEvidenceCommitment 是私有防篡改绑定：把 exact canonical Kind 8 字节、
// Claim ID、冻结仲裁费与重建 candidate raw 绑定在一起，任何对持久化托管状态
// 的篡改都会在 Sign 阶段被发现。它不是第二套 wire 真值，绝不序列化进报文。
func preparedEvidenceCommitment(exactRequestRaw, claimID []byte, arbiterAmountSatoshis uint64, unsigned *pool.UnsignedPayment) []byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("bitfs.v1.arbitration.prepared-arbitration\x00"))
	writeCommitmentPart(hash, exactRequestRaw)
	writeCommitmentPart(hash, claimID)
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], arbiterAmountSatoshis)
	_, _ = hash.Write(number[:])
	writeCommitmentPart(hash, unsigned.RawTx)
	return hash.Sum(nil)
}

func writeCommitmentPart(hash hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(value)
}

// equalUnsigned 报告两份未签名 candidate 是否逐字段逐字节一致。
func equalUnsigned(left, right *pool.UnsignedPayment) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.RefundTemplateTxID == right.RefundTemplateTxID && bytes.Equal(left.RawTx, right.RawTx) && left.PaymentSequence == right.PaymentSequence && left.BuyerAmountSatoshis == right.BuyerAmountSatoshis && left.SellerAmountSatoshis == right.SellerAmountSatoshis && left.ArbiterAmountSatoshis == right.ArbiterAmountSatoshis && left.PoolOutputSatoshis == right.PoolOutputSatoshis && bytes.Equal(left.PoolLockingScript, right.PoolLockingScript)
}

func cloneUnsigned(unsigned *pool.UnsignedPayment) *pool.UnsignedPayment {
	if unsigned == nil {
		return nil
	}
	copied := *unsigned
	copied.RawTx = append([]byte(nil), unsigned.RawTx...)
	copied.PoolLockingScript = append([]byte(nil), unsigned.PoolLockingScript...)
	return &copied
}
