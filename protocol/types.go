package protocol

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/bsv8/go-bitfs/internal/refundlock"
)

// 本文件定义仓库唯一的共享强类型值：哈希、摘要、压缩公钥、聪数、区块高度、
// 付款序号与取回随机数。它们取代角色 API 中含义不明的裸整数与 []byte；
// wire 编码仍按协议使用原始字节/整数值，named type 只属于 SDK 与存储便利层。
//
// 所有 byte parser 检查精确长度、压缩公钥有效性与全零哨兵；Bytes()/切片
// getter 一律返回副本，调用方无法修改内部状态。

var (
	// ErrValueLength 标记字节宽度不等于类型固定宽度的输入。
	ErrValueLength = errors.New("value length does not match the fixed width")
	// ErrZeroValue 标记进入编码、存储或网络路径的全零哨兵值。
	ErrZeroValue = errors.New("all-zero value is rejected")
	// ErrNilInput 标记公开 API 收到 nil 指针或 nil 切片。
	ErrNilInput = errors.New("required input is nil")
)

// Hash32 是固定 32 字节的通用哈希值（例如资金交易 TxID）。
type Hash32 [32]byte

// NewHash32 从精确 32 字节构造 Hash32；拒绝其他长度与全零哨兵。
func NewHash32(raw []byte) (Hash32, error) {
	return newFixed32[Hash32](raw)
}

// Bytes 返回内部字节的副本；调用方修改副本不会影响本值。
func (h Hash32) Bytes() []byte { return append([]byte(nil), h[:]...) }

// IsZero 报告该值是否为全零哨兵；哨兵绝不允许上线。
func (h Hash32) IsZero() bool { return h == Hash32{} }

// String 返回无前缀小写 hex（仅诊断用途；typed ID 才有稳定文本前缀）。
func (h Hash32) String() string { return hexString(h[:]) }

// Digest32 是 SDK 构造好的 32 字节签名摘要：普通消息为 SHA-256(exact
// WireSignatureInput)，交易签名为固定 sighash digest。Signer 只接触本值。
type Digest32 [32]byte

// NewDigest32 从精确 32 字节构造 Digest32；拒绝其他长度与全零哨兵。
func NewDigest32(raw []byte) (Digest32, error) {
	return newFixed32[Digest32](raw)
}

// Bytes 返回内部字节的副本；调用方修改副本不会影响本值。
func (d Digest32) Bytes() []byte { return append([]byte(nil), d[:]...) }

// IsZero 报告该值是否为全零哨兵；哨兵绝不允许上线。
func (d Digest32) IsZero() bool { return d == Digest32{} }

// String 返回无前缀小写 hex（仅诊断用途）。
func (d Digest32) String() string { return hexString(d[:]) }

// PublicKey 是 33 字节压缩 secp256k1 角色公钥的强类型值。
type PublicKey [33]byte

// PublicKeyFromBytes 解析并校验压缩公钥有效性后返回强类型公钥；拒绝非
// canonical 压缩编码、错误长度与全零哨兵。
func PublicKeyFromBytes(raw []byte) (PublicKey, error) {
	var result PublicKey
	if len(raw) != 33 {
		return result, fmt.Errorf("public key must be a 33-byte compressed secp256k1 key")
	}
	if bytes.Equal(raw, make([]byte, 33)) {
		return result, fmt.Errorf("%w: public key", ErrZeroValue)
	}
	key, err := ParseCompressedPubKey(raw)
	if err != nil {
		return result, err
	}
	copy(result[:], key.Compressed())
	return result, nil
}

// Bytes 返回内部字节的副本；调用方修改副本不会影响本值。
func (p PublicKey) Bytes() []byte { return append([]byte(nil), p[:]...) }

// IsZero 报告该值是否为全零哨兵；哨兵绝不允许上线。
func (p PublicKey) IsZero() bool { return p == PublicKey{} }

// String 返回无前缀小写 hex（仅诊断用途）。
func (p PublicKey) String() string { return hexString(p[:]) }

// Satoshis 是协议金额单位：绝对累计或单笔分配的聪数。
type Satoshis uint64

// BlockHeight 是调用方作为显式事实传入的区块高度；0 表示"未提供"，
// 需要高度判断的操作必须拒绝零值。
type BlockHeight uint32

// PaymentSequence 是资金池付款状态链上的序号（1..4294967294）；
// 4294967295 保留给最终关闭。
type PaymentSequence uint32

// RetrievalNonce 是 Kind 10 取回请求的 32 字节重放键。默认入口由 SDK 用
// crypto/rand 生成；显式 nonce 入口只服务测试与恢复路径。
type RetrievalNonce [32]byte

// NewRetrievalNonce 从精确 32 字节构造 RetrievalNonce；拒绝其他长度与
// 全零哨兵。
func NewRetrievalNonce(raw []byte) (RetrievalNonce, error) {
	return newFixed32[RetrievalNonce](raw)
}

// GenerateRetrievalNonce 用 crypto/rand 生成安全随机 nonce；SDK 默认入口
// 使用它，应用不需要也不应该自造弱随机源。
func GenerateRetrievalNonce() (RetrievalNonce, error) {
	var nonce RetrievalNonce
	if _, err := cryptorandRead(nonce[:]); err != nil {
		return RetrievalNonce{}, fmt.Errorf("generate retrieval nonce: %w", err)
	}
	if nonce.IsZero() {
		return RetrievalNonce{}, fmt.Errorf("generate retrieval nonce: %w", ErrZeroValue)
	}
	return nonce, nil
}

// Bytes 返回内部字节的副本；调用方修改副本不会影响本值。
func (n RetrievalNonce) Bytes() []byte { return append([]byte(nil), n[:]...) }

// IsZero 报告该值是否为全零哨兵；哨兵绝不允许上线。
func (n RetrievalNonce) IsZero() bool { return n == RetrievalNonce{} }

// String 返回无前缀小写 hex（仅诊断用途）。
func (n RetrievalNonce) String() string { return hexString(n[:]) }

// newFixed32 是固定 32 字节值的统一构造器：精确长度 + 全零哨兵检查。
func newFixed32[T ~[32]byte](raw []byte) (T, error) {
	var result T
	var zero T
	if len(raw) != 32 {
		return result, fmt.Errorf("%w: got %d bytes, want 32", ErrValueLength, len(raw))
	}
	copy(result[:], raw)
	if result == zero {
		return T{}, fmt.Errorf("%w: 32-byte value", ErrZeroValue)
	}
	return result, nil
}

// RefundLockTime 是退款交易 nLockTime 原始值：低于 TimestampThreshold 为
// 区块高锁定，否则为 UTC 时间戳锁定（解释规则由协议固定）。
type RefundLockTime uint32

// UsesBlockHeight 报告该锁定值是否按区块高解释。
func (t RefundLockTime) UsesBlockHeight() bool { return t < RefundTimestampThreshold }

// RefundTimestampThreshold 引用内部包的唯一定界常量，避免第二份真值。
const RefundTimestampThreshold = refundlock.TimestampThreshold

// SatoshisPerKilobyte 是矿工费率单位：每千字节虚拟大小的聪数。
type SatoshisPerKilobyte uint64
