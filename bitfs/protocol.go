// Package bitfs 提供 BitFS v1 的确定性协议辅助函数。
package bitfs

const (
	// BlockSize 是 BitFS v1 固定 block 大小上限，单位为字节。
	BlockSize uint64 = 256 * 1024

	// SeedContentIndex 表示 HashGetTicket 购买的是 seed，而不是某个 block。
	SeedContentIndex int64 = -1
)
