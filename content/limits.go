package content

import masterseed "github.com/bsv8/MasterSeed"

// BlockSize 与 DigestSize 是 MasterSeed 依赖库拥有的协议常量；本包仅按
// 协议引用它们。
const (
	// BlockSize 是一个完整内容块的字节数（256 KiB）。
	BlockSize uint64 = masterseed.BlockSize
	// DigestSize 是 seed 摘要的字节宽度。
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
