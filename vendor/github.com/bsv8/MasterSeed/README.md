# MasterSeed

MasterSeed 是 Keymaster Seed V1 的 Go 与 TypeScript SDK 项目。

源文件固定按 256 KiB（262144 字节）分块。每个数据块计算 SHA-256，所得 **32 字节原始二进制摘要**按块顺序直接拼接，形成种子文件：

```text
seed_bytes = block_hash[0] || ... || block_hash[n-1]
seed_hash  = SHA256(seed_bytes)
```

种子文件不保存十六进制文本。Hex 仅用于 API、日志和传播时表示 `seed_hash`。

## 项目文档

- [需求文档](./docs/requirements.md)：产品范围、功能需求和验收标准
- [设计文档](./docs/design.md)：V1 二进制格式、算法、SDK API 与错误模型
- [施工单](./docs/implementation-plan.md)：Go、TypeScript、共享测试和发布任务
- [API 摘要](./docs/api.md)：两个 SDK 的公开操作、类型和错误判断方式

实现包含：

- 根目录 Go module：包名 `masterseed`；
- `typescript/`：运行时无关的核心 package；
- `masterseed/node`：Node.js 文件路径适配层；
- `spec/seed-v1.md` 与 `testdata/v1/vectors.json`：公开格式和跨语言黄金向量。

## Go 最小示例

种子文件保存的是原始二进制摘要；下面的 `SeedHashHex` 仅用于展示和传播。

```go
package main

import (
    "context"
    "fmt"
    "github.com/bsv8/MasterSeed"
)

func main() {
    info, err := masterseed.CreateSeedFile(
        context.Background(), "source.bin", "source.seed",
        masterseed.CreateSeedFileOptions{},
    )
    if err != nil { panic(err) }
    fmt.Println(info.SeedHashHex)
}
```

完整源文件验证先取得可信的 `seed_hash`，再调用 `VerifySourceFile`：

```go
expected, err := masterseed.ParseDigestHex(seedHashHex)
if err != nil { panic(err) }
_, err = masterseed.VerifySourceFile(context.Background(), "source.bin", "source.seed", expected)
```

当上层协议还提供可信的源文件大小时，可以同时验证 Seed 的摘要数量，并执行
无索引的块成员查询或块内容验证：

```go
info, err := masterseed.VerifySeedForSourceSize(ctx, bytes.NewReader(seedBytes), expected, sourceSize)
matches, err := masterseed.FindBlockHash(ctx, bytes.NewReader(seedBytes), expected, sourceSize, blockHash)
verified, err := masterseed.VerifyBlockInSeed(ctx, bytes.NewReader(seedBytes), expected, sourceSize, blockBytes)
```

这些流式操作都会读完并认证完整 Seed 后才返回成员结论；`FindBlockHash` 的
`MatchCount == 0` 是正常查询结果。`seed_hash` 和源文件大小的可信来源仍由
调用方的签名、报价或其他上层协议负责。每次调用都会消费 Seed reader；执行
多个操作时必须重新打开文件或为每次调用创建独立的 `bytes.NewReader(seedBytes)`。

## TypeScript 最小示例

核心 API 接收任意 `Uint8Array` 异步 chunk；计数、大小和偏移使用 `bigint`。

```ts
import { createSeed, Digest } from "masterseed";
import { createSeedFile, verifySourceFile } from "masterseed/node";

const info = await createSeed(
  (async function* () { yield new TextEncoder().encode("abc"); })(),
  { async write(bytes) { /* persist all 32 raw bytes */ } }
);
console.log(info.seedHashHex);

await createSeedFile("source.bin", "source.seed");
await verifySourceFile("source.bin", "source.seed", Digest.fromHex(info.seedHashHex));
```

TypeScript 核心入口也对等提供 `verifySeedForSourceSize`、`expectedBlockSize`、
`findBlockHash` 和 `verifyBlockInSeed`；大小、计数和索引继续使用 `bigint`。

默认路径生成禁止覆盖已有目标，并在同目录临时文件完成后才发布。失败或取消会清理临时文件。

## 检查命令

```text
go test ./...
go vet ./...
cd typescript && npm ci && npm run check
```

V1 的 `BLOCK_SIZE`、SHA-256 和原始 32 字节摘要布局是协议常量；需要头部、元数据、其他块大小或其他算法时必须定义新版本，不能修改 V1 文件字节。
