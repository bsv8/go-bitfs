package protocol

import "errors"

// 协议对象 ID 是版本及 Kind 命名空间内的 typed ID：每个文档词根对应独立的
// Go named type，编译器禁止把 Claim ID、payload ID、request ID 等 [32]byte
// 值静默互换。持久化索引必须使用具体类型；编码边界再转换为 CBOR bstr。

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

// IsZero 报告该 ID 是否为全零哨兵；哨兵绝不允许上线。
func (id FileQuoteTermsID) IsZero() bool { return id == FileQuoteTermsID{} }

// IsZero 报告该 ID 是否为全零哨兵；哨兵绝不允许上线。
func (id PaymentAuthorizationID) IsZero() bool { return id == PaymentAuthorizationID{} }

// IsZero 报告该 ID 是否为全零哨兵；哨兵绝不允许上线。
func (id ArbitrationClaimID) IsZero() bool { return id == ArbitrationClaimID{} }

// IsZero 报告该 ID 是否为全零哨兵；哨兵绝不允许上线。
func (id ContentRetrievalRequestID) IsZero() bool { return id == ContentRetrievalRequestID{} }

// IsZero 报告该 ID 是否为全零哨兵；哨兵绝不允许上线。
func (id ContentPayloadsID) IsZero() bool { return id == ContentPayloadsID{} }
