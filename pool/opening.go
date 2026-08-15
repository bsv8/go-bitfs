package pool

import (
	"bytes"
	"context"
	"fmt"

	tx "github.com/bsv-blockchain/go-sdk/transaction"
)

// SpendTxID returns the stable 002 anchor, the transaction ID of the
// unsigned presigned refund evidence. Transaction identity is calculated by
// the fixed SDK transaction parser; applications do not supply a calculator.
func SpendTxID(_ context.Context, proof *OpeningProof) (Hash32, error) {
	if proof == nil {
		return Hash32{}, fmt.Errorf("%w: opening proof is required", ErrInvalidEvidence)
	}
	value, err := parseCanonicalTransaction(proof.RefundTx)
	if err != nil {
		return Hash32{}, err
	}
	computed := hash32FromBytes(value.TxID().CloneBytes())
	if len(proof.SpendTxID) > 0 && !bytes.Equal(proof.SpendTxID, computed[:]) {
		return Hash32{}, fmt.Errorf("%w: spend transaction ID does not match refund transaction", ErrInvalidEvidence)
	}
	return computed, nil
}

// parseCanonicalTransaction is the only parser used for protocol transaction
// identities.  The wire bytes themselves are the transaction identity: a
// parser that accepts an alternate CompactSize encoding must not silently
// canonicalize it before hashing or broadcasting.
func parseCanonicalTransaction(raw []byte) (*tx.Transaction, error) {
	value, err := tx.NewTransactionFromBytes(raw)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(value.Bytes(), raw) {
		return nil, fmt.Errorf("%w: transaction encoding is not canonical", ErrInvalidEvidence)
	}
	return value, nil
}

// ParseCanonicalTransaction parses a protocol transaction only when its raw
// bytes are the SDK's canonical serialization. Workflows use this before
// deriving outpoints, IDs, or signatures.
func ParseCanonicalTransaction(raw []byte) (*tx.Transaction, error) {
	return parseCanonicalTransaction(raw)
}

// RefundUsesBlockHeight deterministically classifies a refund locktime. It
// parses the supplied refund bytes and returns true for Bitcoin nLockTime
// values below the timestamp threshold; malformed bytes are rejected.
func RefundUsesBlockHeight(refundTx []byte) (bool, error) {
	value, err := parseCanonicalTransaction(refundTx)
	if err != nil {
		return false, fmt.Errorf("parse refund transaction: %w", err)
	}
	return value.LockTime < lockTimeTimestampThreshold, nil
}
