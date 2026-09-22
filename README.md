# go-bitfs / TypeScript BitFS SDK

本仓库现在同时维护 Go 与 TypeScript 两种 BitFS Wire Protocol v1 实现。两端使用
strict deterministic CBOR，保留离线验签所需的 exact signed bytes，并共同消费
`fixtures/manifest.json` 指向的 wire、交易、CDDL 与 libp2p transport 真值。

目录与字段含义：

- `protocol/`、`content/`、`pool/`、`buyer/`、`seller/`、`arbiter/`、`wire/`：Go SDK。
- `typescript/src/`：TypeScript 的 Artifact、Kind 1–11 typed encoder、签名域和网络绑定。
- `fixtures/manifest.json`：两种语言测试的唯一真值索引；不能在语言目录复制期望值。
- `transport/` 与 `typescript/src/transport.ts`：`bitcoin-libp2p` uvarint stream 适配。
- `BITFS_PROTOCOL_ID` / `transport.ProtocolID`：libp2p stream 协议标识 `/bitfs/wire/1.0.0`。
- `maxInboundFrameBytes` / `wire.MaxWireParseBytes`：本地单帧接收上限，不发给对端。

网络层直接复用 `github.com/bsv8/bitcoin-libp2p/streamio` 与 npm
`bitcoin-libp2p/stream`。Noise、Yamux、Identify、PeerId 与身份 signer 由
`bitcoin-libp2p` 负责；BitFS 层只发送
`uvarint(exact Artifact 字节数) || exact Artifact bytes`，不增加 JSON envelope、
session ID 或隐藏 pool ID。

The protocol is documented in the multilingual [Docusaurus site](website/README.md). English is the normative website language; Simplified Chinese is maintained under `website/i18n/zh-CN/`.

| Step | Specification | Requirements and intent |
|---:|---|---|
| 001 | [Quote credential](website/docs/protocol/001-quote-credential-spec.md) | [Requirements](website/docs/protocol/001-quote-credential-requirements.md) |
| 002 | [Pool opening](website/docs/protocol/002-pool-opening-spec.md) | [Requirements](website/docs/protocol/002-pool-opening-requirements.md) |
| 003 | [Content request](website/docs/protocol/003-content-request-spec.md) | [Requirements](website/docs/protocol/003-content-request-requirements.md) |
| 004 | [Content delivery](website/docs/protocol/004-content-delivery-spec.md) | [Requirements](website/docs/protocol/004-content-delivery-requirements.md) |
| 005 | [Cumulative payment](website/docs/protocol/005-cumulative-payment-spec.md) | [Requirements](website/docs/protocol/005-cumulative-payment-requirements.md) |
| 006 | [Pool close](website/docs/protocol/006-unconditional-pool-close-spec.md) | [Requirements](website/docs/protocol/006-pool-close-requirements.md) |
| 007 | [Seller arbitration](website/docs/protocol/007-seller-arbitration-submission-spec.md) | [Requirements](website/docs/protocol/007-seller-arbitration-submission-requirements.md) |
| 008 | [Buyer arbitrated content retrieval](website/docs/protocol/008-buyer-arbitrated-content-retrieval-spec.md) | [Requirements](website/docs/protocol/008-buyer-arbitrated-content-retrieval-requirements.md) |

Step 008 is read-only content recovery from arbiter custody. It is **not** a buyer arbitration close: when the seller is unreachable, the buyer either waits or broadcasts its presigned RefundTx after `nLockTime`.

The current CDDL is under `spec/v1/`; retired iterations are archived under `spec/legacy/`. Every complete wire message starts with `[protocol.WireVersion, wire_kind, ...]` and travels as a parsed `wire.Artifact` whose `Bytes()` returns an immutable copy of the exact bytes. Transaction scripts, fees, signatures, and state construction are delegated to the published MultisigPool v4 implementations. The optional libp2p byte transport is standardized by this repository's thin `transport` adapters over `bitcoin-libp2p`; host lifecycle, routing, retries, database adapters, time sources, and block-height sources remain application-owned. Protocol time and height enter explicitly as `protocol.Facts{Now, BlockHeight}` per Go call.

## Quick start

SDK = 无状态计算器 + 验钞机：每个入口只接收原始报文字节、普通证据包与一次调用专用的受约束 Signer，返回原始报文字节或普通证据包。SDK 不持有跨步骤对象、不保存进度、不定价策略、不碰钱包、不广播、不读时钟、不访问存储。应用负责进度、状态机、存储、恢复、重试、对账与广播。

```go
// ---- 步骤 1：三方密钥 → 受约束 Signer（唯一密钥托管端口）。----
signerSeller, err := protocol.NewPrivateKeySigner(sellerKey) // sellerKey 为 *ec.PrivateKey
signerBuyer, err := protocol.NewPrivateKeySigner(buyerKey)

// ---- 步骤 2：显式事实（时间 + 高度）由调用方观测并传入；SDK 不读钟、不查节点。----
facts := protocol.Facts{Now: observedTimeUTC, BlockHeight: 900000}

// ---- 步骤 3（卖方）：签署 001 报价；返回待发送 exact Kind 1 与最终条款。----
outbound, terms, err := seller.CreateQuote(ctx, facts, signerSeller, seller.QuoteDraft{
    SeedHash:                   seedHash,
    BuyerPublicKey:             buyerPubKey,
    SeedPriceSatoshis:          100,
    FullBlockPriceSatoshis:     1000,
    FileSizeBytes:              uint64(len(fileBytes)),
    QuoteExpiresAtUnixSeconds:  content.UnixSeconds(facts.Now.Add(time.Hour).Unix()),
    SupportedArbiterPublicKeys: []protocol.PublicKey{arbiterPubKey},
    RecommendedFilename:        "file.bin", // 先 sanitize 再进入签名条款
})
rawKind1 := outbound.Bytes() // 应用先持久化 exact Kind 1 bytes 再发送

// ---- 步骤 4（买方）：从 exact bytes 验收；应用自行核对 terms.BuyerPublicKey。----
vq, err := buyer.AcceptQuote(facts, rawKind1)

// ---- 步骤 5–6：开池。每一步只接收原始报文与普通证据包，返回普通证据包；
//      SDK 不保存进度，应用先持久化返回的 evidence 再发送 outbound。----
kind2, buyerOpening, err := buyer.PrepareOpening(ctx, buyer.PrepareOpeningInput{
    FundingTransactionRaw: fundingRaw, ExpiryLockTime: expiry,
    MinerFeeRateSatoshisPerKilobyte: 1,
    SellerPublicKey: sellerPubKey, ArbiterPublicKey: arbiterPubKey,
}, signerBuyer)
kind3, sellerOpening, err := seller.PreparePresign(ctx, kind2.Bytes(), signerSeller)
buyerOpening, buyerPool, err := buyer.CompleteOpening(buyerOpening, kind3.Bytes())
kind4, err := buyer.PrepareFundingDelivery(buyerPool)
fundingRaw, sellerPool, err := seller.VerifyFunding(kind4.Bytes(), sellerOpening)

// ---- 步骤 7–9：一轮购买（003→004→005）。----
kind5, authorization, err := buyer.PrepareContentRequest(ctx, facts, buyer.RequestContentInput{
    QuoteRaw: rawKind1, Pool: buyerPool, ContentHashes: hashes,
    DeliveryDeadline: deadlineUnixSeconds, Seed: seedBytes,
}, signerBuyer)                              // → exact Kind 5 + 普通授权证据包
kind6, delivery, err := seller.PrepareDelivery(ctx, facts, seller.DeliveryInput{
    QuoteRaw: rawKind1, Pool: sellerPool, RequestRaw: kind5.Bytes(),
    ContentPayloads: payloads, Seed: seedBytes,
}, signerSeller)                             // → exact Kind 6 + 普通交付证据包
payloads, kind7, err := buyer.VerifyDelivery(ctx, facts, buyer.VerifyDeliveryInput{
    Authorization: authorization, Pool: buyerPool,
    DeliveryRaw: kind6.Bytes(), Seed: seedBytes,
}, signerBuyer)                              // → 已验证 payload + 唯一 exact Kind 7
paymentRaw, sellerPool, err := seller.CompletePayment(ctx, facts, seller.CompletePaymentInput{
    Pool: sellerPool, RequestRaw: kind5.Bytes(), UpdateRaw: kind7.Bytes(),
}, signerSeller)                             // → 完整付款交易 + 付款后的普通证据包
```

买方推进池状态的唯一方式：从链上取得完整付款交易原文，作为普通证据包的 `LatestPaymentRawTx` 传入下一步，由 SDK 全量重验；不存在跳过链上结果的入口。

Error handling branches on stable categories, never on error text:

```go
if _, err := buyer.AcceptQuote(facts, raw); err != nil {
    switch {
    case protocol.IsCode(err, protocol.CodeExpired):
        // 报价过期：按业务策略重新要报价。
    case protocol.IsCode(err, protocol.CodeInvalidSignature):
        // 卖方签名验证失败：拒绝该凭证。
    default:
        // 其余分类见 protocol.ErrorCode（malformed_wire、state_conflict 等）。
    }
}
```

## Packages

- `protocol/`: shared foundations — constrained `Signer` port (+ `NewPrivateKeySigner`), explicit `Facts`, typed IDs, structured errors with `ErrorCode` classification.
- `content/`: quote and content credentials, seeds, hashes, pricing, and evidence validation (001/003/004), plus the immutable `VerifiedQuote` and exported `ClassifyContentHashes`.
- `pool/`: independent 002/005/006 settlement state machine and transaction engine with verified payment-state helpers.
- `buyer/`, `seller/`, `arbiter/`: pure step functions — each entry takes raw wire bytes, plain evidence packages, and a per-call constrained signer.
- `arbitration/`: pure 007/008 custody-evidence domain functions; `wire/`: typed encoders and strict decoders returning `wire.Artifact` values.

Run the test suite with:

```bash
make test
# 或分别运行：
go test ./...
npm ci --prefix typescript && npm test --prefix typescript
```
