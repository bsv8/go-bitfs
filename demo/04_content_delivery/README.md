# 004：卖家原子交付内容批次

这一步演示卖家收到 003 的批量授权后，读取整批内容并构造一个 004 交付：一个交付包原子交付同一批 payload，全有或全无。demo 还会用 SDK 验证交付结构，但不会在这一步完成付款。

角色 workflow 只持有受约束 Signer。003 授权（exact bytes）、报价、池 checkpoint 和内容字节（本例即 seed 原文）全部由 fixture 显式持有并传入；时间与高度来自显式 `Facts{Now, BlockHeight}`。

运行：

```sh
go run ./demo/04_content_delivery/01_deliver_content
```

核心调用是：

```go
result, err := sellerWorkflow.DeliverContent(ctx, facts, seller.DeliveryCommand{
    Quote:           signedQuote,       // 本池对应的已签报价
    Pool:            sellerPoolCheckpoint,
    RequestRaw:      rawKind5,          // 买方发来的 exact Kind 5 bytes
    ContentPayloads: [][]byte{seedBytes}, // 顺序与 003 哈希一一对应
    Seed:            seedBytes,         // 批次包含任何块时必须提供
})
rawKind6 := result.Outbound.Bytes()    // exact Kind 6 bytes：先保存再发送
checkpoint := result.Checkpoint        // DeliveryCheckpoint：先持久化再发送，
                                       // 验收买方付款凭证时原样回传
```

`DeliverContent` 先完整验证原始 003（池绑定、买方统一签名、报价与时间门禁），重算授权 ID，解码 003 已提交的有序哈希，然后逐项验证 payload 数量、顺序、SHA-256、seed/block 归属与协议期望长度，并重算聚合价格与目标序号。全部通过后才签署并返回待发送 Artifact 与记录目标的 `DeliveryCheckpoint`（费用池关联 ID、授权 ID、目标序号、绝对累计卖方金额）。该 checkpoint 由 demo 作为调用方自行保存，供卖方后续 `CompletePayment` 复核使用——SDK 不保存它。

004 是 wire Kind 6 五元确定性 CBOR 外壳，payload 作为 attachment 放在签名字段之后，不直接进入签名预映像：

```text
kind-6-content-delivery = [
    1,                                    // wire-version，由 encoder 注入
    6,                                    // wire kind
    content_delivery_cbor,                // deterministic-CBOR([payment_authorization_id])
    seller_content_delivery_signature,    // 统一消息签名，覆盖精确 content_delivery_cbor
    content_payloads_cbor                 // 规范子 CBOR bstr，顺序与 003 hashes 一一对应
]
```

绑定链完整成立：SellerSignature → content_delivery_cbor → PaymentAuthorizationID → payment_authorization_cbor → ordered content_hashes_cbor + 池 + 序号 + 金额；content_payloads_cbor[i] 的 SHA-256 必须等于 content_hashes_cbor[i]。

买方应用按 `PaymentAuthorizationID` 路由 004 到本地保存的原始 003；本地找不到时只能暂存或请求对端重发 003，不能从 payload 猜测订单或费用池。

标准输出的 `SIGNED_CONTENT_DELIVERY_HEX` 是要传给买家的交付报文。调试输出会显示授权 ID、payload 批次的条数与大小等。

验证成功只说明“卖家对这条付款授权给出了可验证的整批 payload”。买家还需要调用角色 API 的 `VerifyDeliveryAndPreparePayment` 全量验收后生成唯一的付款凭证，再进入累计付款步骤。
