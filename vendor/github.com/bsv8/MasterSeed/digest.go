package masterseed

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// V1 constants are part of the wire format and must not change within V1.
const (
	Format        = "keymaster-seed-v1"
	BlockSize     = 256 * 1024
	DigestSize    = 32
	HashAlgorithm = "SHA-256"
	// Upper-case aliases mirror the protocol notation used in the public spec.
	FORMAT         = Format
	BLOCK_SIZE     = BlockSize
	DIGEST_SIZE    = DigestSize
	HASH_ALGORITHM = HashAlgorithm
)

// Digest is an immutable, fixed-size SHA-256 digest value.
type Digest struct {
	bytes [DigestSize]byte
}

// DigestFromBytes constructs a Digest only from exactly 32 bytes.
func DigestFromBytes(value []byte) (Digest, error) {
	if len(value) != DigestSize {
		return Digest{}, &Error{Code: InvalidHashEncoding, Message: fmt.Sprintf("digest must contain %d bytes", DigestSize)}
	}
	var result Digest
	copy(result.bytes[:], value)
	return result, nil
}

// ParseDigestHex parses exactly 64 hexadecimal characters. Whitespace and 0x
// prefixes are intentionally not accepted.
func ParseDigestHex(value string) (Digest, error) {
	if len(value) != DigestSize*2 {
		return Digest{}, &Error{Code: InvalidHashEncoding, Message: "digest hex must contain exactly 64 characters"}
	}
	decoded := make([]byte, DigestSize)
	if _, err := hex.Decode(decoded, []byte(value)); err != nil {
		return Digest{}, &Error{Code: InvalidHashEncoding, Message: "digest hex contains a non-hexadecimal character", Cause: err}
	}
	return DigestFromBytes(decoded)
}

// DigestFromHex is an alias for ParseDigestHex.
func DigestFromHex(value string) (Digest, error) { return ParseDigestHex(value) }

// NewDigest is an alias for DigestFromBytes for callers that prefer a
// constructor-style name.
func NewDigest(value []byte) (Digest, error) { return DigestFromBytes(value) }

// Sum256 returns the digest of value.
func Sum256(value []byte) Digest { return Digest{bytes: sha256.Sum256(value)} }

// Bytes returns a copy of the raw 32-byte digest.
func (d Digest) Bytes() []byte {
	result := make([]byte, DigestSize)
	copy(result, d.bytes[:])
	return result
}

// Hex returns the canonical lower-case hexadecimal representation.
func (d Digest) Hex() string { return hex.EncodeToString(d.bytes[:]) }

// String implements fmt.Stringer using the canonical hexadecimal form.
func (d Digest) String() string { return d.Hex() }

// Equal compares two digest values.
func (d Digest) Equal(other Digest) bool {
	var difference byte
	for i := range d.bytes {
		difference |= d.bytes[i] ^ other.bytes[i]
	}
	return difference == 0
}

func digestPointer(value Digest) *Digest {
	copy := value
	return &copy
}
