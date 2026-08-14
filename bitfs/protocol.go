// Package bitfs implements the protocol layer for BitFS 001, 003, and 004.
// It owns canonical CBOR, signed quote/content credentials, hashes, and
// payload validation. It does not store files, open pools, or submit network
// transactions; buyer and seller workflows inject those capabilities.
package bitfs

import masterseed "github.com/bsv8/MasterSeed"

const (
	// BlockSize is retained as a compatibility alias. MasterSeed is the
	// authoritative owner of seed protocol constants.
	BlockSize uint64 = masterseed.BlockSize
	// DigestSize is the byte width of a seed digest.
	DigestSize = masterseed.DigestSize
)
