// Package pool contains the protocol-independent 2-of-3 settlement primitives
// used by 002, 005, and 006. It validates role-ordered MultisigPool v4 bytes,
// tracks monotonic payment state, and exposes storage/backend interfaces; it deliberately
// does not import BitFS quote or content types.
package pool

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

var (
	// ErrInvalidEvidence is returned when pool evidence fails structural or protocol validation.
	ErrInvalidEvidence = errors.New("invalid pool evidence")
	// ErrPoolBusy indicates that a pool already has an active delivery.
	ErrPoolBusy = errors.New("pool busy")
	// ErrStalePaymentSequence indicates that an update does not extend current state.
	ErrStalePaymentSequence = errors.New("stale payment sequence")
	// ErrInsufficientBalance indicates that a payment exceeds the pool balance.
	ErrInsufficientBalance = errors.New("insufficient pool balance")
	// ErrNonFinalRejected indicates that the node rejected a non-final payment update.
	ErrNonFinalRejected = errors.New("non-final pool rejected update")
	// ErrFinalRejected indicates that the node rejected a final transaction.
	ErrFinalRejected = errors.New("pool node rejected final transaction")
	// ErrNotExpired indicates that the refund locktime has not yet been reached.
	ErrNotExpired = errors.New("pool refund expiry has not been reached")
	// ErrPoolStateUncertain indicates that node acceptance must be reconciled
	// after local persistence failed.
	ErrPoolStateUncertain = errors.New("pool state requires external reconciliation")
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
