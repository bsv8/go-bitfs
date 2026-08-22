// Package pool contains the protocol-independent 2-of-3 settlement primitives
// used by 002, 005, and 006. It validates role-ordered MultisigPool v4 bytes,
// tracks monotonic payment state, and exposes pure transaction construction,
// parsing, signing, and verification capabilities; it deliberately does not
// import BitFS quote or content types and performs no storage, network, or
// node side effects.
package pool

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/bsv8/go-bitfs/internal/refundlock"
)

var (
	// ErrInvalidEvidence is returned when pool evidence fails structural or protocol validation.
	ErrInvalidEvidence = errors.New("invalid pool evidence")
	// ErrStalePaymentSequence indicates that an update does not extend current state.
	ErrStalePaymentSequence = errors.New("stale payment sequence")
	// ErrInsufficientBalance indicates that a payment exceeds the pool balance.
	ErrInsufficientBalance = errors.New("insufficient pool balance")
	// ErrNotExpired is the internal refundlock sentinel re-exported so callers
	// matching it via errors.Is observe the "not yet matured" condition.
	ErrNotExpired = refundlock.ErrNotExpired
)

func invalid(message string) error { return fmt.Errorf("%w: %s", ErrInvalidEvidence, message) }

func hash32FromBytes(raw []byte) Hash32 {
	var result Hash32
	if len(raw) == sha256.Size {
		copy(result[:], raw)
		return result
	}
	return Hash32(sha256.Sum256(raw))
}
