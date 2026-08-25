package protocol

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// 协议对象 ID 是版本及 Kind 命名空间内的 typed ID：每个文档词根对应独立的
// Go named type，编译器禁止把 Claim ID、payload ID、request ID 等 [32]byte
// 值静默互换。持久化索引必须使用具体类型；编码边界再转换为 CBOR bstr。
//
// 文本编码只属于 SDK/存储便利层：wire 中继续编码原始 32 字节 bstr。文本
// 形式使用稳定类型前缀（fq_/pa_/ac_/cr_/cp_），禁止无类型裸 hex 在日志和
// 通用数据库索引中静默互换。

// FileQuoteTermsID = SHA-256(exact file_quote_terms_cbor)，Kind 1 文档 ID。
type FileQuoteTermsID [32]byte

// PaymentAuthorizationID = SHA-256(exact payment_authorization_cbor)，Kind 5
// 文档 ID，也是 Kind 6/7 的内容寻址键。
type PaymentAuthorizationID [32]byte

// ArbitrationClaimID = SHA-256(exact arbitration_claim_cbor)，Kind 8 文档 ID，
// 同时路由 Kind 9 回执与 Kind 10 取件请求。
type ArbitrationClaimID [32]byte

// ContentRetrievalRequestID = SHA-256(exact content_retrieval_request_cbor)，
// Kind 10 文档 ID，绑定 Kind 11 的两种分支响应。
type ContentRetrievalRequestID [32]byte

// ContentPayloadsID = SHA-256(exact content_payloads_cbor)，Kind 11 available
// 分支绑定的 payload 集合 ID。它不替代 payment authorization 中逐块的
// content hashes。
type ContentPayloadsID [32]byte

// ErrZeroIdentifier 标记进入编码、存储或网络路径的全零哨兵 ID。
var ErrZeroIdentifier = errors.New("all-zero identifier is rejected")

// idTextPrefixes 是各 typed ID 的稳定类型前缀：日志与数据库索引必须能区分
// 五类 ID，禁止裸 hex 混用。
const (
	prefixFileQuoteTermsID          = "fq_"
	prefixPaymentAuthorizationID    = "pa_"
	prefixArbitrationClaimID        = "ac_"
	prefixContentRetrievalRequestID = "cr_"
	prefixContentPayloadsID         = "cp_"
)

// Bytes 返回内部字节的副本；调用方修改副本不会影响本 ID。
func (id FileQuoteTermsID) Bytes() []byte { return append([]byte(nil), id[:]...) }

// IsZero 报告该 ID 是否为全零哨兵；哨兵绝不允许上线。
func (id FileQuoteTermsID) IsZero() bool { return id == FileQuoteTermsID{} }

// String 返回带稳定类型前缀 fq_ 的小写 hex 文本；仅用于 SDK/存储/日志层。
func (id FileQuoteTermsID) String() string { return prefixedID(prefixFileQuoteTermsID, id[:]) }

// MarshalText 实现 encoding.TextMarshaler：输出带 fq_ 前缀的小写 hex。
func (id FileQuoteTermsID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText 实现 encoding.TextMarshaler 的解码侧：只接受 fq_ 前缀的
// 64 位小写/大写 hex，全零哨兵拒绝。
func (id *FileQuoteTermsID) UnmarshalText(text []byte) error {
	value, err := parsePrefixedID[FileQuoteTermsID](string(text), prefixFileQuoteTermsID)
	if err != nil {
		return err
	}
	*id = value
	return nil
}

// ParseFileQuoteTermsID 解析带 fq_ 前缀的文本 ID。
func ParseFileQuoteTermsID(text string) (FileQuoteTermsID, error) {
	return parsePrefixedID[FileQuoteTermsID](text, prefixFileQuoteTermsID)
}

// NewFileQuoteTermsID 从精确 32 字节构造 ID；拒绝其他长度与全零哨兵。
func NewFileQuoteTermsID(raw []byte) (FileQuoteTermsID, error) {
	return newTypedID[FileQuoteTermsID](raw)
}

// Bytes 返回内部字节的副本；调用方修改副本不会影响本 ID。
func (id PaymentAuthorizationID) Bytes() []byte { return append([]byte(nil), id[:]...) }

// IsZero 报告该 ID 是否为全零哨兵；哨兵绝不允许上线。
func (id PaymentAuthorizationID) IsZero() bool { return id == PaymentAuthorizationID{} }

// String 返回带稳定类型前缀 pa_ 的小写 hex 文本；仅用于 SDK/存储/日志层。
func (id PaymentAuthorizationID) String() string {
	return prefixedID(prefixPaymentAuthorizationID, id[:])
}

// MarshalText 实现 encoding.TextMarshaler：输出带 pa_ 前缀的小写 hex。
func (id PaymentAuthorizationID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText 实现 encoding.TextMarshaler 的解码侧：只接受 pa_ 前缀。
func (id *PaymentAuthorizationID) UnmarshalText(text []byte) error {
	value, err := parsePrefixedID[PaymentAuthorizationID](string(text), prefixPaymentAuthorizationID)
	if err != nil {
		return err
	}
	*id = value
	return nil
}

// ParsePaymentAuthorizationID 解析带 pa_ 前缀的文本 ID。
func ParsePaymentAuthorizationID(text string) (PaymentAuthorizationID, error) {
	return parsePrefixedID[PaymentAuthorizationID](text, prefixPaymentAuthorizationID)
}

// NewPaymentAuthorizationID 从精确 32 字节构造 ID；拒绝其他长度与全零哨兵。
func NewPaymentAuthorizationID(raw []byte) (PaymentAuthorizationID, error) {
	return newTypedID[PaymentAuthorizationID](raw)
}

// Bytes 返回内部字节的副本；调用方修改副本不会影响本 ID。
func (id ArbitrationClaimID) Bytes() []byte { return append([]byte(nil), id[:]...) }

// IsZero 报告该 ID 是否为全零哨兵；哨兵绝不允许上线。
func (id ArbitrationClaimID) IsZero() bool { return id == ArbitrationClaimID{} }

// String 返回带稳定类型前缀 ac_ 的小写 hex 文本；仅用于 SDK/存储/日志层。
func (id ArbitrationClaimID) String() string { return prefixedID(prefixArbitrationClaimID, id[:]) }

// MarshalText 实现 encoding.TextMarshaler：输出带 ac_ 前缀的小写 hex。
func (id ArbitrationClaimID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText 实现 encoding.TextMarshaler 的解码侧：只接受 ac_ 前缀。
func (id *ArbitrationClaimID) UnmarshalText(text []byte) error {
	value, err := parsePrefixedID[ArbitrationClaimID](string(text), prefixArbitrationClaimID)
	if err != nil {
		return err
	}
	*id = value
	return nil
}

// ParseArbitrationClaimID 解析带 ac_ 前缀的文本 ID。
func ParseArbitrationClaimID(text string) (ArbitrationClaimID, error) {
	return parsePrefixedID[ArbitrationClaimID](text, prefixArbitrationClaimID)
}

// NewArbitrationClaimID 从精确 32 字节构造 ID；拒绝其他长度与全零哨兵。
func NewArbitrationClaimID(raw []byte) (ArbitrationClaimID, error) {
	return newTypedID[ArbitrationClaimID](raw)
}

// Bytes 返回内部字节的副本；调用方修改副本不会影响本 ID。
func (id ContentRetrievalRequestID) Bytes() []byte { return append([]byte(nil), id[:]...) }

// IsZero 报告该 ID 是否为全零哨兵；哨兵绝不允许上线。
func (id ContentRetrievalRequestID) IsZero() bool { return id == ContentRetrievalRequestID{} }

// String 返回带稳定类型前缀 cr_ 的小写 hex 文本；仅用于 SDK/存储/日志层。
func (id ContentRetrievalRequestID) String() string {
	return prefixedID(prefixContentRetrievalRequestID, id[:])
}

// MarshalText 实现 encoding.TextMarshaler：输出带 cr_ 前缀的小写 hex。
func (id ContentRetrievalRequestID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText 实现 encoding.TextMarshaler 的解码侧：只接受 cr_ 前缀。
func (id *ContentRetrievalRequestID) UnmarshalText(text []byte) error {
	value, err := parsePrefixedID[ContentRetrievalRequestID](string(text), prefixContentRetrievalRequestID)
	if err != nil {
		return err
	}
	*id = value
	return nil
}

// ParseContentRetrievalRequestID 解析带 cr_ 前缀的文本 ID。
func ParseContentRetrievalRequestID(text string) (ContentRetrievalRequestID, error) {
	return parsePrefixedID[ContentRetrievalRequestID](text, prefixContentRetrievalRequestID)
}

// NewContentRetrievalRequestID 从精确 32 字节构造 ID；拒绝其他长度与全零哨兵。
func NewContentRetrievalRequestID(raw []byte) (ContentRetrievalRequestID, error) {
	return newTypedID[ContentRetrievalRequestID](raw)
}

// Bytes 返回内部字节的副本；调用方修改副本不会影响本 ID。
func (id ContentPayloadsID) Bytes() []byte { return append([]byte(nil), id[:]...) }

// IsZero 报告该 ID 是否为全零哨兵；哨兵绝不允许上线。
func (id ContentPayloadsID) IsZero() bool { return id == ContentPayloadsID{} }

// String 返回带稳定类型前缀 cp_ 的小写 hex 文本；仅用于 SDK/存储/日志层。
func (id ContentPayloadsID) String() string { return prefixedID(prefixContentPayloadsID, id[:]) }

// MarshalText 实现 encoding.TextMarshaler：输出带 cp_ 前缀的小写 hex。
func (id ContentPayloadsID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText 实现 encoding.TextMarshaler 的解码侧：只接受 cp_ 前缀。
func (id *ContentPayloadsID) UnmarshalText(text []byte) error {
	value, err := parsePrefixedID[ContentPayloadsID](string(text), prefixContentPayloadsID)
	if err != nil {
		return err
	}
	*id = value
	return nil
}

// ParseContentPayloadsID 解析带 cp_ 前缀的文本 ID。
func ParseContentPayloadsID(text string) (ContentPayloadsID, error) {
	return parsePrefixedID[ContentPayloadsID](text, prefixContentPayloadsID)
}

// NewContentPayloadsID 从精确 32 字节构造 ID；拒绝其他长度与全零哨兵。
func NewContentPayloadsID(raw []byte) (ContentPayloadsID, error) {
	return newTypedID[ContentPayloadsID](raw)
}

// prefixedID 组装 "prefix + 小写 hex" 文本形式。
func prefixedID(prefix string, raw []byte) string {
	return prefix + hex.EncodeToString(raw)
}

// parsePrefixedID 只接受指定前缀 + 恰好 64 个 hex 字符的文本；前缀不符或
// 全零哨兵都拒绝。
func parsePrefixedID[T ~[32]byte](text, prefix string) (T, error) {
	var result T
	var zero T
	if !strings.HasPrefix(text, prefix) {
		return result, fmt.Errorf("%w: identifier text must use the %q type prefix", ErrValueLength, prefix)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(text, prefix))
	if err != nil || len(raw) != 32 {
		return result, fmt.Errorf("%w: identifier body must be 64 hex characters", ErrValueLength)
	}
	copy(result[:], raw)
	if result == zero {
		return T{}, ErrZeroIdentifier
	}
	return result, nil
}

// newTypedID 是 typed ID 的统一字节构造器：精确长度 + 全零哨兵检查。
func newTypedID[T ~[32]byte](raw []byte) (T, error) {
	var result T
	var zero T
	if len(raw) != 32 {
		return result, fmt.Errorf("%w: got %d bytes, want 32", ErrValueLength, len(raw))
	}
	copy(result[:], raw)
	if result == zero {
		return T{}, ErrZeroIdentifier
	}
	return result, nil
}
