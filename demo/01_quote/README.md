# 001：报价单

这一组 demo 演示协议的第一步：买家还没有卖家提供的文件时，先表达“我需要这个文件”，卖家根据文件和交易条件生成 `SignedFileQuote`，买家再解析并验证报价。

这里的两个程序分别放在两个目录中，因为一个 Go package 只能有一个 `main` 函数：

- `01_build_quote`：卖家生成报价单。
- `02_parse_quote`：买家输入报价单并验证、解析报价单。

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

`FILE_PATH` 指向卖家要报价的文件，例如 `demo/file.bin`。`QUOTE_VALID_FOR` 是相对有效期，例如 `1h`、`30m` 或 `24h`，程序用“当前 UTC 时间 + 有效期”计算 `ExpiresAt`，不会使用固定过期时间。

报价中的 `RECOMMENDED_FILENAME` 展示字段会自动取 `FILE_PATH` 的文件名，不需要再单独配置。

## 卖家生成报价单

```sh
go run ./demo/01_quote/01_build_quote
```

程序的标准输出只有最终的报价单 hex，方便保存或传给下一个程序：

```sh
go run ./demo/01_quote/01_build_quote > quote.hex
```

详细调试信息写入标准错误，包括：

- 文件大小、随机 `MasterSeed`、`SeedHash`；
- 从私钥推导出的卖家、买家、仲裁人公钥；
- `FileQuoteTerms` 的字段、CBOR 和 `TermsHash`；
- 报价有效期、单 seed 价格、完整文件价格；
- 卖家签名、最终 `SignedFileQuote` 的 CBOR 大小和 hex 长度。

核心调用可以理解为：

```text
masterSeed = RandomBytes(...)
terms = FileQuoteTerms{
    FileSize:       stat(FILE_PATH).Size,
    SeedHash:       SHA256(masterSeed),
    PricePerSeed:   SEED_PRICE_SAT,
    PriceFullBlock: FULL_BLOCK_PRICE_SAT,
    ExpiresAt:      now + QUOTE_VALID_FOR,
    BuyerPubKey:    pub(BUYER_PRIVATE_KEY_HEX),
    ArbiterPubKeys: [pub(ARBITER_PRIVATE_KEY_HEX)],
}
signedQuote = NewSignedFileQuote(terms, sellerPrivateKey)
quoteHex = EncodeSignedFileQuote(signedQuote)
```

`quote.hex` 是 `bitfs.EncodeSignedFileQuote` 产生的规范 hex。应用真正通过 wire 层传输时，可以再把它包装成：

```go
payload := wire.Marshal(wire.Quote, signedQuote)
```

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

买家会依次显示 hex 解码、CBOR 解码、卖家签名、有效期、买家公钥绑定、价格和仲裁人字段的检查结果。成功后会打印解析出的字段；错误输入会明确指出失败阶段，例如 hex、CBOR、签名、过期时间或买家绑定错误。

伪代码如下：

```text
signedQuote = DecodeSignedFileQuote(inputHex)
VerifySellerSignature(signedQuote)
CheckExpiresAt(signedQuote.Terms.ExpiresAt, now)
expectedBuyer = pub(BUYER_PRIVATE_KEY_HEX)
require(signedQuote.Terms.BuyerPubKey == expectedBuyer)
print(signedQuote.Terms)
```

这个 demo 直接调用 `bitfs.NewSignedFileQuote`，没有强行创建完整的 `seller.Workflow`。因为仅生成报价只需要纯函数式的签名与编码能力；后面的 demo 再用只持有官方 BSV 私钥的无状态 workflow 和 fixture 把这些步骤串起来。
