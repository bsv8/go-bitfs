package bitfs

import (
	"crypto/sha256"
	"fmt"
)

// ContentHash 校验交付长度并计算 content_hash。
// 所有对象，包括最后一个残块，都直接哈希真实 payload，绝不补零。
func ContentHash(contentIndex int64, expectedSize uint64, payload []byte) ([sha256.Size]byte, error) {
	if contentIndex < SeedContentIndex {
		return [sha256.Size]byte{}, fmt.Errorf("invalid content_index %d", contentIndex)
	}
	if uint64(len(payload)) != expectedSize {
		return [sha256.Size]byte{}, fmt.Errorf("payload length %d does not match expected_size %d", len(payload), expectedSize)
	}
	if contentIndex != SeedContentIndex && (expectedSize == 0 || expectedSize > BlockSize) {
		return [sha256.Size]byte{}, fmt.Errorf("invalid block expected_size %d", expectedSize)
	}
	if contentIndex == SeedContentIndex && expectedSize%sha256.Size != 0 {
		return [sha256.Size]byte{}, fmt.Errorf("seed expected_size must be a multiple of %d, got %d", sha256.Size, expectedSize)
	}
	return sha256.Sum256(payload), nil
}
