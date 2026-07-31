package bitfs

import "errors"

// Sentinel errors are stable categories for callers implementing retry,
// rejection and user-facing error handling.
var (
	ErrInvalidEvidence      = errors.New("invalid evidence")
	ErrQuoteExpired         = errors.New("quote expired")
	ErrDeliveryDeadline     = errors.New("delivery deadline expired")
	ErrPoolBusy             = errors.New("pool busy")
	ErrStalePaymentSequence = errors.New("stale payment sequence")
	ErrInsufficientBalance  = errors.New("insufficient balance")
	ErrNonFinalRejected     = errors.New("non-final pool rejected update")
	ErrContentNotInSeed     = errors.New("content is not listed by seed")
)
