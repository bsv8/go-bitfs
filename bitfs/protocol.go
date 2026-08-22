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

// MaxContentBatchItems 是一条 003 授权或一个 004 交付包允许携带的内容条目数。
//
// 该上限是协议真值：content_hashes 与 content_payloads 子 CBOR 数组长度必须
// 在 1 到 64 之间。超过 64 个内容时，调用方必须拆成多个连续付款序号的 003
// 批次；SDK 不做自动拆分、截断或去重。
const MaxContentBatchItems = 64

// MaxContentPayloadsCBORBytes 是 004 中 content_payloads_cbor 子文档的最大字节数。
//
// 公式为 MaxContentBatchItems*(masterseed.BlockSize+9)+9：每个最大长度的
// bstr 条目占用 BlockSize 字节加最多 9 字节的 CBOR 头部，外加最多 9 字节的
// 数组头部。在解码子数组之前先按该上限拒绝超长输入，防止单个恶意 bstr 绕过
// 数组数量限制。它是 SDK 的协议上限，不是部署层的 HTTP body 或消息配额；
// 应用仍必须设置不高于自身可承受能力的资源上限。
const MaxContentPayloadsCBORBytes = MaxContentBatchItems*(int(masterseed.BlockSize)+9) + 9
