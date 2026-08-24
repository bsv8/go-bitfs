---
id: 001-quote-credential-spec
title: 001 · BitFS 报价凭证规范
---

# 001 · BitFS 报价凭证规范

## 编码、签名与哈希

所有结构使用 RFC 8949 core deterministic CBOR。报价是 wire Kind 1：固定五元外壳，卖方签名通过统一 `SignWireDocument(1, 1, ...)` 覆盖 exact `file_quote_terms_cbor`——类型化签名输入 `["bitfs/wire-signature", 1, 1, file_quote_terms_cbor]` 把版本和 Kind 与精确文档字节一起纳入认证。不存在对裸哈希的签名。

```text
kind-1-file-quote = [
    1,                                  ; wire-version，由 encoder 固定注入
    1,                                  ; wire kind
    file_quote_terms_cbor,
    seller_public_key,
    seller_file_quote_terms_signature   ; SignWireDocument(1, 1, ...)
]

file_quote_terms_id = SHA-256(file_quote_terms_cbor)
```

规范 CDDL 真值位于 [`spec/v1/wire-messages.cddl`](https://github.com/bsv8/go-bitfs/blob/main/spec/v1/wire-messages.cddl)。

## `FileQuoteTerms`

CBOR 数组位置固定如下：

| 位置 | 字段 | 实施要求 |
|---:|---|---|
| 0 | `seed_hash` | 必须为 32 字节。 |
| 1 | `buyer_public_key` | 仅该压缩公钥可接受并签署后续购买请求。 |
| 2 | `seed_price_satoshis` | seed 价格，单位 satoshi。 |
| 3 | `full_block_price_satoshis` | 完整块价格，单位 satoshi。 |
| 4 | `file_size_bytes` | 文件总字节数。 |
| 5 | `quote_expires_at_unix_seconds` | 报价失效 Unix 秒时间。 |
| 6 | `supported_arbiter_public_keys_cbor` | 仲裁公钥数组的独立 deterministic CBOR。 |
| 7 | `recommended_filename` | 经 sanitize 的展示建议；与其他条款一样由卖方签名。 |

认证文档不携带版本或 Kind 字段。块数必须由 `file_size_bytes` 推导：`0` 对应 `0` 块；正数对应 `ceil(file_size_bytes / 262144)`。每个 payload 不超过一个 MasterSeed 块（256 KiB）。仲裁公钥数组可为空，但其中公钥不得为空或重复。`recommended_filename` 必须先通过 sanitize 规则再编码和签名；因为它进入条款，仅文件名不同的两份报价具有不同的 `file_quote_terms_id`。

## `SignedFileQuote`

SDK 类型携带 exact 子文档字节加卖方公钥与签名：

```text
file_quote_terms_cbor              ; 精确规范字节，绝不重编码
seller_public_key                  ; 验证条款统一签名
seller_file_quote_terms_signature  ; SignWireDocument(1, 1, ...)
```

验证时必须严格解码并确定性重编码 `file_quote_terms_cbor`，用恢复的卖方公钥验证统一签名，然后校验字段宽度、报价期限和仲裁者数组。客户端展示文件名时必须清理路径分隔符和控制字符；验证只检查收到的字段已满足同一 sanitize 规则，绝不静默改写。

## 后续引用与保存

003 付款授权只携带 `file_quote_terms_id`。卖方必须按该 ID 找到并重新验证原始报价凭证；双方必须保存完整报价凭证至关联付款结算与仲裁窗口结束。离线验证、迁移或仲裁时，完整报价凭证与后续凭证组成证据包。

## 尾块

报价不传尾块价格。实现按实际尾块长度相对于一个 MasterSeed 块的比例计算，并采用卖方 10% 计算误差让利规则。该规则不是自动仲裁的唯一整数公式；005 中买方签出的累计金额是最终可执行金额。

## Go API

```go
arbiterCBOR, err := bitfs.EncodeSupportedArbiterPublicKeys(arbiterPublicKeys)
terms := &bitfs.FileQuoteTerms{
    SeedHash:                       seedHash,
    BuyerPublicKey:                 buyerPublicKey,
    SeedPriceSatoshis:              10,
    FullBlockPriceSatoshis:         100,
    FileSizeBytes:                  fileSizeBytes,
    QuoteExpiresAtUnixSeconds:      expiresAtUnixSeconds,
    SupportedArbiterPublicKeysCBOR: arbiterCBOR,
}
quote, err := bitfs.NewSignedFileQuote(terms, sellerPrivateKey, "download.bin")
verifiedTerms, err := bitfs.VerifyFileQuoteEvidence(quote)
quoteID, err := bitfs.FileQuoteTermsID(quote.FileQuoteTermsCBOR)
```

workflow 只持有官方 BSV 私钥；签名与验证都走固定的 `SignWireDocument(1, 1, ...)` helper，调用方无需提供签名域、验签回调或曲线实现。
