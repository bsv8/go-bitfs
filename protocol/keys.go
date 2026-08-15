// Package protocol contains small, shared wire-level validation helpers.
package protocol

import (
	"bytes"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// ParseCompressedPubKey parses a protocol identity key. Protocol identity
// fields carry only the canonical 33-byte compressed secp256k1 form; accepting
// an equivalent uncompressed encoding would change signed wire bytes.
func ParseCompressedPubKey(raw []byte) (*ec.PublicKey, error) {
	if len(raw) != 33 {
		return nil, fmt.Errorf("public key must be a 33-byte compressed secp256k1 key")
	}
	key, err := ec.ParsePubKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse compressed public key: %w", err)
	}
	compressed := key.Compressed()
	if !bytes.Equal(raw, compressed) {
		return nil, fmt.Errorf("public key is not the canonical compressed encoding")
	}
	return key, nil
}

// ValidateCompressedPubKey validates a protocol identity public key and
// rejects non-canonical or uncompressed representations.
func ValidateCompressedPubKey(raw []byte) error {
	_, err := ParseCompressedPubKey(raw)
	return err
}
