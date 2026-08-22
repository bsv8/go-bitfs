package bitfs

import "errors"

// Sentinel errors are stable categories for callers implementing retry,
// rejection and user-facing error handling.
var (
	ErrInvalidEvidence      = errors.New("invalid evidence")
	ErrQuoteExpired         = errors.New("quote expired")
	ErrDeliveryDeadline     = errors.New("delivery deadline expired")
	ErrStalePaymentSequence = errors.New("stale payment sequence")
	ErrInsufficientBalance  = errors.New("insufficient balance")
	ErrContentNotInSeed     = errors.New("content is not listed by seed")
)
