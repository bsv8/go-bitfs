# go-bitfs

go-bitfs is the source of truth for the BitFS Wire Protocol v1 Go implementation: file exchange, arbitration, and 2-of-3 MultisigPool settlement. The implementation uses strict deterministic CBOR and preserves the exact signed bytes required for offline verification.

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

The current CDDL is under `spec/v1/`; retired iterations are archived under `spec/legacy/`. Every complete wire message starts with `[protocol.WireVersion, wire_kind, ...]` and travels as a parsed `wire.Artifact` whose `Bytes()` returns an immutable copy of the exact bytes. Transaction scripts, fees, signatures, and state construction are delegated to the published `github.com/bsv8/MultisigPool/v4` implementation. Network, queue, WebSocket, database adapters, time sources, and block-height sources remain application-owned interfaces supplied explicitly as `protocol.Facts{Now, BlockHeight}` per call.

## Quick start

The only recommended path is the role workflow API. Keys enter through one constrained signer port (`protocol.Signer`; local software keys use `protocol.NewPrivateKeySigner`), time and height enter through one explicit facts value, and every outbound message is an exact-bytes `wire.Artifact` that the application persists before sending:

```go
// ---- 步骤 1：三方密钥 → 受约束 Signer（唯一密钥托管端口）。----
signerSeller, err := protocol.NewPrivateKeySigner(sellerKey) // sellerKey 为 *ec.PrivateKey
signerBuyer, err := protocol.NewPrivateKeySigner(buyerKey)

// ---- 步骤 2：角色 workflow 只持有 Signer；无存储、无时钟、无网络。----
sellerWf, err := seller.NewWorkflow(signerSeller)
buyerWf, err := buyer.NewWorkflow(signerBuyer)

// ---- 步骤 3：显式事实（时间 + 高度）由调用方观测并传入；SDK 不读钟、不查节点。----
facts := protocol.Facts{Now: observedTimeUTC, BlockHeight: 900000}

// ---- 步骤 4（卖方）：签署 001 报价，得到待发送 Artifact。----
qr, err := sellerWf.CreateQuote(ctx, facts, seller.QuoteDraft{
    SeedHash:                   seedHash,
    BuyerPublicKey:             buyerPubKey,
    SeedPriceSatoshis:          100,
    FullBlockPriceSatoshis:     1000,
    FileSizeBytes:              uint64(len(fileBytes)),
    QuoteExpiresAtUnixSeconds:  facts.Now.Add(time.Hour).Unix(),
    SupportedArbiterPublicKeys: [][]byte{arbiterPubKey},
    RecommendedFilename:        "file.bin", // 先 sanitize 再进入签名条款
})
rawKind1 := qr.Outbound.Bytes() // 应用先持久化 exact Kind 1 bytes 再发送

// ---- 步骤 5（买方）：从 exact bytes 验收，得到不可变 VerifiedQuote。----
vq, err := buyerWf.AcceptQuote(ctx, facts, rawKind1)

// ---- 步骤 6–7：开池（买方 PreparePoolOpening → 卖方 PreparePoolOpening
//      → 买方 CompletePoolOpening → PrepareFundingDelivery → 卖方
//      VerifyFundingDelivery），每个 Result 都先持久化 Checkpoint 再发送
//      Outbound；广播边界属于应用。----

// ---- 步骤 8–10：一轮购买。----
rc, err := buyerWf.RequestContent(ctx, facts, buyer.RequestContentCommand{
    Quote: vq, Pool: poolCheckpoint, ContentHashes: hashes,
    DeliveryDeadline: deadlineUnixSeconds, Seed: seedBytes,
})                                   // → Kind 5 Artifact + AuthorizationCheckpoint
dr, err := sellerWf.DeliverContent(ctx, facts, seller.DeliveryCommand{
    Quote: signedQuote, Pool: sellerPool, RequestRaw: rawKind5,
    ContentPayloads: payloads, Seed: seedBytes,
})                                   // → Kind 6 Artifact + DeliveryCheckpoint
pp, err := buyerWf.VerifyDeliveryAndPreparePayment(ctx, facts, buyer.VerifyDeliveryCommand{
    Quote: vq, Pool: poolCheckpoint, Request: rc.Checkpoint,
    DeliveryRaw: rawKind6, Seed: seedBytes,
})                                   // → 验证 payload + 唯一 Kind 7 凭证
cp, err := sellerWf.CompletePayment(ctx, facts, seller.PaymentCommand{
    Pool: sellerPool, Request: signedRequest, UpdateRaw: rawKind7,
    Checkpoint: dr.Checkpoint,
})                                   // → 完整付款交易 + 双方推进后的池 checkpoint
```

Error handling branches on stable categories, never on error text:

```go
if _, err := buyerWf.AcceptQuote(ctx, facts, raw); err != nil {
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
- `content/`: quote and content credentials, seeds, hashes, pricing, and evidence validation (001/003/004), plus the immutable `VerifiedQuote`.
- `pool/`: independent 002/005/006 settlement state machine and transaction engine with opaque verified values.
- `buyer/`, `seller/`, `arbiter/`: role workflows — the only recommended entry path for applications.
- `arbitration/`: pure 007/008 custody-evidence domain functions; `wire/`: typed encoders and strict decoders returning `wire.Artifact` values.

Run the test suite with:

```bash
go test ./...
```
