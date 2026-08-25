# 001：报价单

这一组 demo 演示协议的第一步：买家还没有卖家提供的文件时，先表达“我需要这个文件”，卖家根据文件和交易条件签署报价，买家再从 exact bytes 验收报价。

这里的两个程序分别放在两个目录中，因为一个 Go package 只能有一个 `main` 函数：

- `01_build_quote`：卖家生成报价单。
- `02_parse_quote`：买家输入报价单并验收、解析报价单。

## 运行前准备

所有 demo 共用一个 `demo/.env`。第一次使用时复制模板：

```sh
cp demo/.env.example demo/.env
```

然后填入卖家、买家、仲裁人的 64 位十六进制私钥。仓库中的 `.gitignore` 已忽略 `.env` 和 `.value` 文件；如果使用私钥文件，建议放在 `demo/secrets/`，并限制权限：

```sh
mkdir -p demo/secrets
chmod 700 demo/secrets
chmod 600 demo/secrets/*.value
```

程序会自动读取仓库根目录下的 `demo/.env`。已经存在的系统环境变量优先级更高，所以也可以在命令行中临时覆盖配置。程序不会打印私钥。

`FILE_PATH` 指向卖家要报价的文件，例如 `demo/file.bin`。`QUOTE_VALID_FOR` 是相对有效期，例如 `1h`、`30m` 或 `24h`，程序用“当前 UTC 时间 + 有效期”计算 `QuoteExpiresAtUnixSeconds`，不会使用固定过期时间。

报价的 `RecommendedFilename` 展示字段会自动取 `FILE_PATH` 的文件名（SDK 会先 sanitize 再纳入被签条款），不需要再单独配置。

## 卖家生成报价单

```sh
go run ./demo/01_quote/01_build_quote
```

程序的标准输出只有最终的 exact Kind 1 Artifact hex，方便保存或传给下一个程序：

```sh
go run ./demo/01_quote/01_build_quote > quote.hex
```

详细调试信息写入标准错误，包括：

- 文件大小、随机 `MasterSeed`、`SeedHash`；
- 从私钥推导出的卖家、买家、仲裁人公钥；
- 显式事实 `Facts{Now, BlockHeight}` 的观测值与最终签署的过期时间；
- 最终条款快照（sanitize 后的文件名、单价等）；
- 完整 Kind 1 Artifact 的字节数。

核心调用就是角色 API 主路径：

```go
// 私钥只经受约束 Signer 进入；workflow 不持有第二构造路径。
signer, _ := protocol.NewPrivateKeySigner(sellerPrivateKey)
sellerWorkflow, _ := seller.NewWorkflow(signer)

// 显式事实：Now 是本操作唯一时间事实；SDK 不读系统时钟。
facts := protocol.Facts{Now: time.Now().UTC(), BlockHeight: blockHeight}

// QuoteDraft 是唯一条款来源；返回待发送 Artifact 与实际签署的最终 terms。
quoteResult, err := sellerWorkflow.CreateQuote(ctx, facts, seller.QuoteDraft{
    SeedHash:                   seedHash,
    BuyerPublicKey:             buyerPubKey,
    SeedPriceSatoshis:          seedPriceSat,
    FullBlockPriceSatoshis:     fullBlockPriceSat,
    FileSizeBytes:              uint64(len(fileBytes)),
    QuoteExpiresAtUnixSeconds:  facts.Now.Add(validFor).Unix(),
    SupportedArbiterPublicKeys: [][]byte{arbiterPubKey},
    RecommendedFilename:        filename,
})

rawKind1 := quoteResult.Outbound.Bytes() // 应用先持久化 exact bytes 再发送
```

标准输出的 hex 就是 `quoteResult.Outbound.Bytes()` 的 exact 字节；应用真正传输时直接发送它，接收方把它交给买方角色 API 验收。`quoteResult.Terms` 是最终规范化并已签署的条款快照，用于展示实际签署值（含 sanitize 后的文件名）。

## 买家解析报价单

直接运行时，程序会提示输入一行报价单 hex：

```sh
go run ./demo/01_quote/02_parse_quote
```

也可以从文件读取，或者直接和卖家程序连接：

```sh
go run ./demo/01_quote/02_parse_quote < quote.hex
go run ./demo/01_quote/01_build_quote | go run ./demo/01_quote/02_parse_quote
```

买家会依次显示 hex 解码、报文自描述 Kind、卖方签名、有效期（以 `Facts.Now` 判断）、买家公钥绑定、价格和仲裁人字段的检查结果。成功后会打印解析出的字段；错误输入按稳定分类拒绝（畸形报文、验签失败、过期、角色不匹配），不会匹配错误文本。

伪代码如下：

```go
// 展示层：wire.Parse 自读版本与 Kind 并分派严格 decoder。
artifact, err := wire.Parse(rawQuote)

// 业务验收全部在角色 API 内完成：严格解析 + 卖方验签 + 以 facts.Now 判过期，
// 返回不可变 VerifiedQuote。
signer, _ := protocol.NewPrivateKeySigner(buyerPrivateKey)
buyerWorkflow, _ := buyer.NewWorkflow(signer)
verified, err := buyerWorkflow.AcceptQuote(ctx, facts, rawQuote)

terms := verified.Terms()                       // 最终规范化条款
_ = verified.ID().String()                      // 报价 typed ID
_ = verified.SupportedArbiterPublicKeys()       // 允许的仲裁公钥列表
if !bytes.Equal(terms.BuyerPublicKey, myCompressedPubKey) {
    // 角色绑定检查由应用显式补充展示；AcceptQuote 内部同样强制校验。
}
```

两个程序都走同一条新主路径：私钥 → `protocol.NewPrivateKeySigner` → 角色 workflow → 角色 API。没有绕过 workflow 的第二条签名入口；后续 demo 用同样的方式把步骤串起来。
