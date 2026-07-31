package bitfs

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

// BuildSeedBytes 按 BitFS v1 的唯一格式构造 seed：仅顺序拼接 32 字节 block hash。
func BuildSeedBytes(blockHashes [][]byte) ([]byte, error) {
	seed := make([]byte, 0, len(blockHashes)*sha256.Size)
	for index, blockHash := range blockHashes {
		if len(blockHash) != sha256.Size {
			return nil, fmt.Errorf("block hash #%d length must be %d, got %d", index, sha256.Size, len(blockHash))
		}
		seed = append(seed, blockHash...)
	}
	return seed, nil
}

// ParseSeedBytes 按 BitFS v1 的唯一格式解析 seed，并返回独立副本的 block hash 列表。
func ParseSeedBytes(seed []byte) ([][]byte, error) {
	if len(seed)%sha256.Size != 0 {
		return nil, fmt.Errorf("seed length must be a multiple of %d, got %d", sha256.Size, len(seed))
	}
	blockHashes := make([][]byte, 0, len(seed)/sha256.Size)
	for offset := 0; offset < len(seed); offset += sha256.Size {
		blockHashes = append(blockHashes, append([]byte(nil), seed[offset:offset+sha256.Size]...))
	}
	return blockHashes, nil
}

// SeedHash 计算 BitFS v1 seed 的 sha256 摘要。
func SeedHash(seed []byte) [sha256.Size]byte {
	return sha256.Sum256(seed)
}

// BlockHashInSeed reports whether a block hash is one of the ordered hashes
// committed by seed.  The seed itself is checked against the quote before the
// membership result is returned.
func BlockHashInSeed(seed, quoteSeedHash, blockHash []byte) (bool, error) {
	if len(quoteSeedHash) != sha256.Size || len(blockHash) != sha256.Size {
		return false, fmt.Errorf("%w: seed and block hashes must be 32 bytes", ErrInvalidEvidence)
	}
	digest := SeedHash(seed)
	if !bytes.Equal(digest[:], quoteSeedHash) {
		return false, fmt.Errorf("%w: seed hash does not match quote", ErrInvalidEvidence)
	}
	blockHashes, err := ParseSeedBytes(seed)
	if err != nil {
		return false, fmt.Errorf("%w: parse seed: %v", ErrInvalidEvidence, err)
	}
	for _, candidate := range blockHashes {
		if bytes.Equal(candidate, blockHash) {
			return true, nil
		}
	}
	return false, ErrContentNotInSeed
}
