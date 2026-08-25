package protocol

import (
	"errors"
	"fmt"
	"strings"
)

// ErrorCode 是仓库唯一稳定的错误分类。应用只能依据 Code/类型做分支，
// 绝不能匹配错误文本（英文或中文）。
type ErrorCode string

const (
	// CodeMalformedWire 表示报文结构、数组形状或字段宽度畸形。
	CodeMalformedWire ErrorCode = "malformed_wire"
	// CodeNonCanonical 表示结构合法但编码不是 deterministic CBOR。
	CodeNonCanonical ErrorCode = "non_canonical"
	// CodeUnsupportedVersion 表示 wire version 不是 1。
	CodeUnsupportedVersion ErrorCode = "unsupported_version"
	// CodeUnsupportedKind 表示 Kind 不在 1..11 或与路由声明不一致。
	CodeUnsupportedKind ErrorCode = "unsupported_kind"
	// CodeInvalidSignature 表示普通消息签名或交易签名验证失败（含
	// 畸形 DER、high-S、空签名、公钥不匹配）。
	CodeInvalidSignature ErrorCode = "invalid_signature"
	// CodeInvalidEvidence 表示密码学/证据链/业务约束拒绝：哈希不匹配、
	// 池绑定失败、金额守恒破坏等。
	CodeInvalidEvidence ErrorCode = "invalid_evidence"
	// CodeUnauthorized 表示角色公钥与操作者身份不符。
	CodeUnauthorized ErrorCode = "unauthorized"
	// CodeExpired 表示报价过期、交付截止已过或退款锁定已到期。
	CodeExpired ErrorCode = "expired"
	// CodeNotMatured 表示退款锁定尚未到期（正向操作被拒）。
	CodeNotMatured ErrorCode = "not_matured"
	// CodeStateConflict 表示序号陈旧、checkpoint 与证据错配等本地状态冲突。
	CodeStateConflict ErrorCode = "state_conflict"
	// CodeInsufficientBalance 表示付款超出资金池余额或容量。
	CodeInsufficientBalance ErrorCode = "insufficient_balance"
	// CodeCanceled 表示调用方 context 取消或超时。
	CodeCanceled ErrorCode = "canceled"
	// CodeSignerUnavailable 表示密钥托管方暂时无法完成签名；SDK 绝不降级。
	CodeSignerUnavailable ErrorCode = "signer_unavailable"
)

// Error 是全仓统一的结构化错误：Op 描述操作路径，Code 用于稳定分支，
// Kind 标注相关 wire Kind（0 表示无），Field 只携带安全的字段路径名，
// Cause 保留底层原因供 errors.Is/As 追溯。错误字段绝不回显私钥、完整
// payload、签名 preimage、raw transaction 或多租户存在性信息。
type Error struct {
	// Op 是产生错误的 SDK 操作名（如 "buyer.AcceptQuote"），仅用于开发诊断。
	Op string
	// Code 是稳定错误分类；应用分支只看它。
	Code ErrorCode
	// Kind 是相关的 wire Kind（1..11）；无关联时为 0。
	Kind uint16
	// Field 是安全的相关字段/子文档路径名；可为空。
	Field string
	// Cause 是底层原因；可为 nil。errors.Is 穿透本链。
	Cause error
}

// NewError 构造一个结构化错误；cause 可为 nil。
func NewError(op string, code ErrorCode, kind uint16, field string, cause error) *Error {
	return &Error{Op: op, Code: code, Kind: kind, Field: field, Cause: cause}
}

// Errorf 是无底层 cause 的便捷构造器。
func Errorf(op string, code ErrorCode, kind uint16, field, format string, args ...any) *Error {
	return &Error{Op: op, Code: code, Kind: kind, Field: field, Cause: fmt.Errorf(format, args...)}
}

// Wrap 把底层 err 分类包装为 *Error；err 为 nil 时返回 nil，便于直接 return。
func Wrap(err error, op string, code ErrorCode, kind uint16, field string) error {
	if err == nil {
		return nil
	}
	return &Error{Op: op, Code: code, Kind: kind, Field: field, Cause: err}
}

// WrapClassified 是"保分类"包装：错误链上已有稳定分类（CodeOf 命中）时原样
// 透传该分类，绝不覆盖；链上没有任何分类时才落到 CodeInvalidEvidence。
//
// 它专用于包装可能携带多种分类的底层门禁结果（如退款门禁会返回 expired/
// not_matured/invalid_evidence）：调用方只补充 Op/Kind/Field 上下文，不得把
// "事实缺失（invalid_evidence）"误报成"expired/not_matured"这类协议状态结论，
// 否则应用按稳定 Code 分支时会得到错误的语义。需要附加消息时必须用 %w 保持
// 错误链（errors.Is(ErrFactsMissing) 等哨兵判断不能断）。
func WrapClassified(err error, op string, kind uint16, field string) error {
	code, ok := CodeOf(err)
	if !ok {
		code = CodeInvalidEvidence
	}
	return Wrap(err, op, code, kind, field)
}

// Error 实现 error 接口；格式面向开发诊断："op: [code] message"。
func (e *Error) Error() string {
	var b strings.Builder
	if e == nil {
		return "<nil>"
	}
	if e.Op != "" {
		b.WriteString(e.Op)
		b.WriteString(": ")
	}
	fmt.Fprintf(&b, "[%s]", e.Code)
	if e.Field != "" {
		b.WriteString(" ")
		b.WriteString(e.Field)
		b.WriteString(":")
	}
	if e.Cause != nil {
		b.WriteString(" ")
		b.WriteString(e.Cause.Error())
	}
	return b.String()
}

// Unwrap 让 errors.Is / errors.As 沿 Cause 链追溯。
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// IsCode 报告错误链的最外层稳定分类是否等于 code：errors.As 只命中链上
// 第一个（最外层）*Error，本函数不继续向内层搜索，不要误读为全链扫描。
// 调用方按稳定 Code 分支用它或 CodeOf；包装层一律经 WrapClassified 保留
// 底层分类，因此最外层判断即等价于业务语义。
func IsCode(err error, code ErrorCode) bool {
	var target *Error
	if errors.As(err, &target) {
		return target.Code == code
	}
	return false
}

// CodeOf 返回错误链中第一个 *Error 的分类；找不到时返回 false。
func CodeOf(err error) (ErrorCode, bool) {
	var target *Error
	if errors.As(err, &target) && target != nil {
		return target.Code, true
	}
	return "", false
}
