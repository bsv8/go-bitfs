// Package bitfs 提供 BitFS v1 的确定性协议辅助函数。
package bitfs

const (
	// BlockSize 是 BitFS v1 固定 block 大小上限，单位为字节。
	BlockSize uint64 = 256 * 1024

	// SeedContentIndex 表示 HashGetTicketV1 购买的是 seed，而不是某个 block。
	SeedContentIndex int64 = -1

	// ProtocolID 是 BitFS 传输协议的 libp2p 标识建议值。
	ProtocolID = "/bsv8/bitfs/transfer/1.0.0"
)
