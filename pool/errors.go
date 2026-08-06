// Package pool contains the generic 2-of-3 settlement primitives. It does
// not import BitFS quote or content types.
package pool

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

var (
	ErrInvalidEvidence      = errors.New("invalid pool evidence")
	ErrPoolBusy             = errors.New("pool busy")
	ErrStalePaymentSequence = errors.New("stale payment sequence")
	ErrInsufficientBalance  = errors.New("insufficient pool balance")
	ErrNonFinalRejected     = errors.New("non-final pool rejected update")
	ErrFinalRejected        = errors.New("pool node rejected final transaction")
	ErrNotExpired           = errors.New("pool refund expiry has not been reached")
	ErrPoolStateUncertain   = errors.New("pool state requires external reconciliation")
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
