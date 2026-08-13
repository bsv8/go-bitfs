// Package bitfs implements the protocol layer for BitFS 001, 003, and 004.
// It owns canonical CBOR, signed quote/content credentials, hashes, and
// payload validation. It does not store files, open pools, or submit network
// transactions; buyer and seller workflows inject those capabilities.
package bitfs

const (
	// BlockSize is the fixed block size limit in bytes.
	BlockSize uint64 = 256 * 1024
)
