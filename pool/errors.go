// Package pool contains the generic 2-of-3 settlement primitives. It does
// not import BitFS quote or content types.
package pool

import "errors"

var (
	ErrInvalidEvidence      = errors.New("invalid pool evidence")
	ErrPoolBusy             = errors.New("pool busy")
	ErrStalePaymentSequence = errors.New("stale payment sequence")
	ErrInsufficientBalance  = errors.New("insufficient pool balance")
	ErrNonFinalRejected     = errors.New("non-final pool rejected update")
	ErrFinalRejected        = errors.New("pool node rejected final transaction")
	ErrNotExpired           = errors.New("pool refund expiry has not been reached")
)
