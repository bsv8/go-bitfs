---
id: 001-quote-credential-spec
title: 001 · BitFS 报价凭证规范
---

# 001 · BitFS 报价凭证规范

## 编码、签名与哈希

所有结构使用 RFC 8949 core deterministic CBOR。`TermsCBOR` 必须是 `FileQuoteTerms` 的原始确定性 CBOR 字节：

```text
TermsSignature = Sign_seller(TermsCBOR)
Verify(SellerPubkey, TermsCBOR, TermsSignature)
FileQuoteTermsHash = SHA256(TermsCBOR)
```

不使用签名域。实现必须只把 `TermsSignature` 按上述报价条款验证。

正式 CDDL 位于 [`https://github.com/bsv8/go-bitfs/blob/main/spec/file-quote.cddl`](https://github.com/bsv8/go-bitfs/blob/main/spec/file-quote.cddl)。

## `FileQuoteTerms`

CBOR 数组位置固定如下：

| 位置 | 字段 | 实施要求 |
|---:|---|---|
| 0 | `version` | 当前为 `1`。 |
| 1 | `seed_hash` | 必须为 32 字节。 |
| 2 | `buyer_pubkey` | 仅该公钥可接受并签署后续购买请求。 |
| 3 | `seed_price_sat` | seed 价格，单位 sat。 |
| 4 | `full_block_price_sat` | 完整 256 KiB 块价格，单位 sat。 |
| 5 | `file_size` | 文件总字节数。 |
| 6 | `quote_expires_at_unix` | 报价失效 Unix 秒时间。 |
| 7 | `supported_arbiter_pubkeys_cbor` | 仲裁公钥数组的独立 deterministic CBOR。 |

块数必须由 `file_size` 推导：`0` 对应 `0` 块；正数对应 `ceil(file_size / 262144)`。当前 seed payload 上限为 256 KiB；报价最大为 8192 块。仲裁公钥数组可为空，但其中公钥不得为空或重复。

## `SignedFileQuote`

CBOR 数组位置固定如下：

| 位置 | 字段 | 实施要求 |
|---:|---|---|
| 0 | `version` | 当前为 `1`。 |
| 1 | `terms_cbor` | 完整 `FileQuoteTerms` 原始 CBOR。 |
| 2 | `seller_pubkey` | 用于验证条款签名。 |
| 3 | `terms_signature` | 卖方对 `terms_cbor` 的签名。 |
| 4 | `recommended_filename` | 仅展示建议；不得作为内容、价格或身份真值。 |

验证时必须重新解码并确定性重编码 `terms_cbor`，验证签名、字段长度、报价期限和仲裁者数组。客户端展示文件名时必须清理路径分隔符和控制字符。

## 后续引用与保存

003 正常报文只携带 `FileQuoteTermsHash`。卖方必须按该哈希找到并重新验证原始报价凭证；双方必须保存完整报价凭证至关联付款结算与仲裁窗口结束。离线验证、迁移或仲裁时，完整报价凭证与后续凭证组成证据包。

## 尾块

报价不传尾块价格。实现按实际尾块长度相对于 256 KiB 的比例计算，并采用卖方 10% 计算误差让利规则。该规则不是 V1 自动仲裁的唯一整数公式；005 中买方签出的累计金额是最终可执行金额。

## Go API

```go
arbiterCBOR, err := bitfs.EncodeSupportedArbiterPubkeys(arbiterPubkeys)
terms := &bitfs.FileQuoteTerms{
    SeedHash:                    seedHash,
    BuyerPubkey:                 buyerPubkey,
    SeedPriceSat:                10,
    FullBlockPriceSat:           100,
    FileSize:                    fileSize,
    QuoteExpiresAtUnix:          expiresAtUnix,
    SupportedArbiterPubkeysCBOR: arbiterCBOR,
}
quote, err := bitfs.NewSignedFileQuote(terms, sellerPubkey, "download.bin", signTermsCBOR)
verifiedTerms, err := bitfs.VerifySignedFileQuote(quote, verifySellerTermsSignature)
```

调用方统一规定公钥格式、签名算法和验签器；库不绑定钱包或曲线实现。
