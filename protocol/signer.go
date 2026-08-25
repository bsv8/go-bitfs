package protocol

import (
	"context"
	"errors"
	"fmt"
)

// SigningPurpose 标记一次签名请求的业务目的，只供 HSM/KMS 策略审计；
// 它不进入也不替代任何既定签名预映像。
type SigningPurpose uint8

const (
	// PurposeWireMessage 是普通 wire 报文签名：Digest = SHA-256(exact
	// WireSignatureInput)，WireKind 携带 1..11。
	PurposeWireMessage SigningPurpose = 1
	// PurposeTransaction 是 MultisigPool 交易签名：Digest 为固定 ForkID|All
	// sighash digest，WireKind 固定为 0；sighash flag 由 pool 装配时添加，
	// Signer 不能选择 flag。
	PurposeTransaction SigningPurpose = 2
)

// String 返回 purpose 的稳定诊断名称；不进入 wire 或日志策略之外的场景。
func (p SigningPurpose) String() string {
	switch p {
	case PurposeWireMessage:
		return "wire_message"
	case PurposeTransaction:
		return "transaction"
	default:
		return fmt.Sprintf("unknown_purpose(%d)", uint8(p))
	}
}

// SigningRequest 描述一次受约束的密钥操作：SDK 已经构造好唯一 digest，
// Signer 只对该 32 字节摘要执行 secp256k1 签名，返回不带交易 sighash flag
// 的 low-S DER。私钥、seed、WIF、助记词和签名请求原文不得进入错误、日志、
// wire 或 checkpoint。
type SigningRequest struct {
	// Purpose 声明业务目的（wire_message / transaction）；仅供密钥托管侧审计。
	Purpose SigningPurpose
	// WireKind 是普通 wire 签名的 Kind（1..11）；交易签名为 0。
	WireKind uint16
	// Digest 是 SDK 构造好的 32 字节签名摘要；Signer 绝不能自行哈希。
	Digest Digest32
}

// ErrSignerUnavailable 表示 Signer 托管方（HSM/KMS/远程服务）暂时无法完成
// 本次密钥操作。SDK 不做本地降级；应用按自身策略对同一 prepared 输入重试。
var ErrSignerUnavailable = errors.New("signer did not return a signature")

// Signer 是 SDK 唯一的密钥操作端口：固定公钥 + 对给定 digest 的 secp256k1
// 签名。Signer 不能提供自定义 hash、preimage、sighash、Verifier、CBOR
// encoder、价格规则或角色判断；所有验签固定在 SDK 内部执行。
type Signer interface {
	// PublicKey 返回本 Signer 的固定压缩公钥；Workflow 构造时固定并验证它，
	// 生命周期内不得变化。
	PublicKey() PublicKey
	// Sign 对 request.Digest 做 secp256k1 签名，返回不带 sighash flag 的
	// DER 字节。context 只用于取消远程签名或长计算；实现遇到托管故障时
	// 返回错误（可包装 ErrSignerUnavailable），绝不能返回空签名或部分结果。
	Sign(ctx context.Context, request SigningRequest) ([]byte, error)
}

// boundSigner 是构造时冻结公钥的 Signer 包装器：PublicKey 永远返回绑定值，
// 与底层实现后续可能发生的密钥轮换完全解耦。Workflow 构造时用它包装外部
// Signer，保证所有下游自验（普通消息签名与交易 sighash）都固定对照角色
// 公钥——远程托管中途换钥只会得到 invalid_signature/unauthorized，绝不可能
// 把新身份静默写入任何 Kind。
type boundSigner struct {
	delegate  Signer
	publicKey PublicKey
}

func (s *boundSigner) PublicKey() PublicKey { return s.publicKey }

func (s *boundSigner) Sign(ctx context.Context, request SigningRequest) ([]byte, error) {
	return s.delegate.Sign(ctx, request)
}

var _ Signer = (*boundSigner)(nil)

// BindSigner 冻结并校验一个 Signer 的当前公钥，返回生命周期内公钥不变的
// 绑定视图。nil 或无效公钥直接拒绝。角色 Workflow 必须经它进入签名能力。
func BindSigner(signer Signer) (Signer, error) {
	if signer == nil {
		return nil, Errorf("protocol.BindSigner", CodeSignerUnavailable, 0, "signer", "signer is required")
	}
	publicKey := signer.PublicKey()
	if err := ValidatePublicKey(publicKey); err != nil {
		return nil, Wrap(fmt.Errorf("signer public key: %v", err), "protocol.BindSigner", CodeInvalidEvidence, 0, "public_key")
	}
	return &boundSigner{delegate: signer, publicKey: publicKey}, nil
}
