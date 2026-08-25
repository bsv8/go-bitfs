// Package pool contains the protocol-independent 2-of-3 settlement primitives
// used by 002, 005, and 006. It validates role-ordered MultisigPool v4 bytes,
// tracks monotonic payment state, and exposes pure transaction construction,
// parsing, signing, and verification capabilities; it deliberately does not
// import BitFS quote or content types and performs no storage, network, or
// node side effects. All signing capability enters through the constrained
// protocol.Signer port; all time/height judgments arrive as explicit facts.
package pool

import (
	"crypto/sha256"

	"github.com/bsv8/go-bitfs/protocol"
)

// invalid 构造本包统一的 invalid_evidence 结构化错误；message 只携带安全的
// 字段路径与类别，不回显私钥、完整 payload、签名 preimage 或 raw transaction。
func invalid(message string) error {
	return protocol.Errorf("pool", protocol.CodeInvalidEvidence, 0, "", "%s", message)
}

// malformedWire 构造结构畸形错误。
func malformedWire(field string, cause error) error {
	return protocol.Wrap(cause, "pool", protocol.CodeMalformedWire, 0, field)
}

// nonCanonical 构造非规范编码错误。
func nonCanonical(field string, message string) error {
	return protocol.Errorf("pool", protocol.CodeNonCanonical, 0, field, "%s", message)
}

// staleSequence 构造序号陈旧/状态冲突错误。
func staleSequence(message string) error {
	return protocol.Errorf("pool", protocol.CodeStateConflict, 0, "payment_sequence", "%s", message)
}

// insufficientBalance 构造余额不足错误。
func insufficientBalance() error {
	return protocol.Errorf("pool", protocol.CodeInsufficientBalance, 0, "seller_amount_after_satoshis", "payment exceeds the pool balance")
}

func hash32FromBytes(raw []byte) Hash32 {
	var result Hash32
	if len(raw) == sha256.Size {
		copy(result[:], raw)
		return result
	}
	return Hash32(sha256.Sum256(raw))
}
