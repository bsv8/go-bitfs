package bitfs

import (
	"crypto/sha256"
	"errors"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/protocol"
)

// SignMessage 是协议固定的消息签名入口：对 payload 做一次 SHA-256，再用
// 官方 BSV 私钥对该摘要签名，返回 low-S DER 签名。私钥只进入本函数的运行时
// 参数，绝不进入 CBOR、报文、本地结果、日志或错误文本。
func SignMessage(key *ec.PrivateKey, payload []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("private key is required")
	}
	digest := sha256.Sum256(payload)
	signature, err := key.Sign(digest[:])
	if err != nil {
		return nil, err
	}
	return signature.ToDER()
}

// VerifySignature is the protocol's fixed ECDSA verifier. The supplied payload
// is hashed with SHA-256 exactly once before DER ECDSA verification. Workflows
// use this implementation directly; callers only provide a public key and the
// exact signed bytes, never a verifier strategy.
func VerifySignature(pubkey, payload, signature []byte) error {
	key, err := protocol.ParseCompressedPubKey(pubkey)
	if err != nil {
		return err
	}
	sig, err := ec.ParseDERSignature(signature)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if !sig.Verify(digest[:], key) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}
