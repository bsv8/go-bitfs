package protocol

import (
	"context"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// PrivateKeySigner 是官方 BSV *ec.PrivateKey 的唯一本地 Signer 适配器：
// 直接私钥只能通过它进入 Workflow，绝不存在"Workflow 同时接受 Signer 和
// 私钥"的第二条路径。私钥不外泄：本类型不暴露任何读取私钥的方法，签名
// 请求原文（digest）与返回值也绝不进入错误、日志、wire 或 checkpoint。
type PrivateKeySigner struct {
	key       *ec.PrivateKey
	publicKey PublicKey
}

// NewPrivateKeySigner 校验并封装一把软件私钥；nil 与无法派生压缩公钥的
// 输入直接拒绝。
func NewPrivateKeySigner(privateKey *ec.PrivateKey) (*PrivateKeySigner, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("%w: private key is required", ErrNilInput)
	}
	compressed := privateKey.PubKey().Compressed()
	publicKey, err := PublicKeyFromBytes(compressed)
	if err != nil {
		return nil, fmt.Errorf("private key public point: %w", err)
	}
	return &PrivateKeySigner{key: privateKey, publicKey: publicKey}, nil
}

// PublicKey 返回构造时固定下来的压缩公钥；生命周期内不变。
func (s *PrivateKeySigner) PublicKey() PublicKey {
	if s == nil {
		return PublicKey{}
	}
	return s.publicKey
}

// Sign 对 SDK 给出的 32 字节 digest 执行 secp256k1 签名并返回 low-S DER
// （不带交易 sighash flag）。本适配器是纯本地计算，不消耗 context；
// nil context 原样接受且绝不替换为 context.Background()。
func (s *PrivateKeySigner) Sign(_ context.Context, request SigningRequest) ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, fmt.Errorf("%w: private key signer is not initialized", ErrNilInput)
	}
	if request.Digest.IsZero() {
		return nil, fmt.Errorf("sign digest: %w", ErrZeroValue)
	}
	signature, err := s.key.Sign(request.Digest.Bytes())
	if err != nil {
		return nil, err
	}
	der, err := signature.ToDER()
	if err != nil {
		return nil, err
	}
	if len(der) == 0 {
		return nil, ErrSignerUnavailable
	}
	return der, nil
}

// 编译期断言：PrivateKeySigner 满足 Signer。
var _ Signer = (*PrivateKeySigner)(nil)
