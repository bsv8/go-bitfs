package masterseed

import (
	"context"
	"errors"
	"fmt"
)

// ErrorCode is stable across the Go and TypeScript SDKs.
type ErrorCode string

const (
	InvalidSeedLength    ErrorCode = "INVALID_SEED_LENGTH"
	InvalidHashEncoding  ErrorCode = "INVALID_HASH_ENCODING"
	SeedHashMismatch     ErrorCode = "SEED_HASH_MISMATCH"
	BlockHashMismatch    ErrorCode = "BLOCK_HASH_MISMATCH"
	SourceTooShort       ErrorCode = "SOURCE_TOO_SHORT"
	SourceTooLong        ErrorCode = "SOURCE_TOO_LONG"
	BlockIndexOutOfRange ErrorCode = "BLOCK_INDEX_OUT_OF_RANGE"
	IntegerOverflow      ErrorCode = "INTEGER_OVERFLOW"
	TargetExists         ErrorCode = "TARGET_EXISTS"
	ReadFailed           ErrorCode = "READ_FAILED"
	WriteFailed          ErrorCode = "WRITE_FAILED"
	Aborted              ErrorCode = "ABORTED"
	InvalidArgument      ErrorCode = "INVALID_ARGUMENT"
	SeedSizeMismatch     ErrorCode = "SEED_SIZE_MISMATCH"
	BlockNotInSeed       ErrorCode = "BLOCK_NOT_IN_SEED"
	BlockSizeMismatch    ErrorCode = "BLOCK_SIZE_MISMATCH"
)

// Error is the structured error returned by the SDK. Context fields are
// optional and are populated only when relevant to the failure.
type Error struct {
	Code               ErrorCode
	Message            string
	Cause              error
	Operation          string
	Path               string
	BlockIndex         *uint64
	BlockCount         *uint64
	SourceOffset       *uint64
	SeedSize           *uint64
	ExpectedSeedSize   *uint64
	ExpectedBlockCount *uint64
	ActualBlockSize    *uint64
	Expected           *Digest
	Actual             *Digest
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Cause }

// CodeOf extracts a stable SDK error code through wrapped errors.
func CodeOf(err error) ErrorCode {
	var sdkErr *Error
	if errors.As(err, &sdkErr) {
		return sdkErr.Code
	}
	return ""
}

// IsCode reports whether err or one of its causes has code.
func IsCode(err error, code ErrorCode) bool { return CodeOf(err) == code }

func errorWithCause(code ErrorCode, operation string, cause error) error {
	if cause == nil {
		return &Error{Code: code, Operation: operation}
	}
	if IsCode(cause, code) {
		return cause
	}
	return &Error{Code: code, Operation: operation, Cause: cause, Message: cause.Error()}
}

func contextOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func checkContext(ctx context.Context) error {
	ctx = contextOrBackground(ctx)
	select {
	case <-ctx.Done():
		return &Error{Code: Aborted, Cause: ctx.Err(), Message: ctx.Err().Error()}
	default:
		return nil
	}
}

func readError(operation string, cause error) error {
	if cause == context.Canceled || cause == context.DeadlineExceeded || errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return &Error{Code: Aborted, Operation: operation, Cause: cause, Message: cause.Error()}
	}
	return errorWithCause(ReadFailed, operation, cause)
}

func writeError(operation string, cause error) error {
	if cause == context.Canceled || cause == context.DeadlineExceeded || errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return &Error{Code: Aborted, Operation: operation, Cause: cause, Message: cause.Error()}
	}
	return errorWithCause(WriteFailed, operation, cause)
}

func invalidArgument(message string) error {
	return &Error{Code: InvalidArgument, Message: message}
}
