// Package protocol 是仓库唯一的共享基础层：强类型值、显式外部事实 Facts、
// 受约束 Signer 端口、typed ID、固定签名域与统一错误模型。它不依赖任何
// 领域包或角色包，也不做存储、网络、时钟或节点副作用。
package protocol

import (
	"bytes"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// ParsePublicKey 解析协议身份公钥并返回强类型 PublicKey。协议身份字段只
// 接受 canonical 33 字节压缩 secp256k1 形式；接受等价非压缩编码会改变签名
// 的 wire 字节。
func ParsePublicKey(raw []byte) (PublicKey, error) {
	return PublicKeyFromBytes(raw)
}

// ValidatePublicKey 校验强类型公钥输入：nil 切片、错误长度与全零哨兵都拒绝。
func ValidatePublicKey(key PublicKey) error {
	if key.IsZero() {
		return fmt.Errorf("%w: public key", ErrZeroValue)
	}
	_, err := ParseCompressedPubKey(key[:])
	return err
}

// ParseCompressedPubKey 解析一个协议身份密钥字节并返回底层 EC 公钥（SDK
// 引擎内部使用）。Protocol identity fields carry only the canonical 33-byte
// compressed secp256k1 form; accepting an equivalent uncompressed encoding
// would change signed wire bytes.
func ParseCompressedPubKey(raw []byte) (*ec.PublicKey, error) {
	if len(raw) != 33 {
		return nil, fmt.Errorf("public key must be a 33-byte compressed secp256k1 key")
	}
	key, err := ec.ParsePubKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse compressed public key: %w", err)
	}
	compressed := key.Compressed()
	if !bytes.Equal(raw, compressed) {
		return nil, fmt.Errorf("public key is not the canonical compressed encoding")
	}
	return key, nil
}

// ValidateCompressedPubKey validates a protocol identity public key and
// rejects non-canonical or uncompressed representations.
func ValidateCompressedPubKey(raw []byte) error {
	_, err := ParseCompressedPubKey(raw)
	return err
}
