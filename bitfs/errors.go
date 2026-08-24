package bitfs

import (
	"errors"

	"github.com/bsv8/go-bitfs/protocol"
)

// Sentinel errors are stable categories for callers implementing retry,
// rejection and user-facing error handling.
var (
	ErrInvalidEvidence      = errors.New("invalid evidence")
	ErrQuoteExpired         = errors.New("quote expired")
	ErrDeliveryDeadline     = errors.New("delivery deadline expired")
	ErrStalePaymentSequence = errors.New("stale payment sequence")
	ErrInsufficientBalance  = errors.New("insufficient balance")
	ErrContentNotInSeed     = errors.New("content is not listed by seed")
	// ErrZeroIdentifier 转发协议层的全零哨兵 ID 拒绝，保持错误分类单一真值。
	ErrZeroIdentifier = protocol.ErrZeroIdentifier
)
