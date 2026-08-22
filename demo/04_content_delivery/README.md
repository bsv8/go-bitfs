# 004：卖家交付内容

这一步演示卖家收到 003 的需求后，读取内容并生成 `SignedContentDelivery`。demo 还会用协议的验证函数检查交付报文，但不会在这一步完成 005 的付款。

go-bitfs SDK 无状态：workflow 只持有官方 BSV 私钥。003 请求、报价、开池证据、最新付款状态和内容字节（本例即 seed 原文）全部由 fixture 显式持有并传入；SDK 不保存任何中间状态。

运行：

```sh
go run ./demo/04_content_delivery/01_deliver_content
```

核心调用是：

```text
delivery, deliveryState = seller.BuildContentDelivery(
    quote, opening, previousPayment, request,
    ContentDeliveryInput{Content: seedBytes}, now)
VerifySignedContentDeliveryAt(request, delivery, quote, now)
```

卖家的 `BuildContentDelivery` 针对显式传入的证据验证 003 请求，返回交付报文和一个 `ContentDeliveryState`（基础序号、基础与预期卖方金额）。该 state 是卖方的本地角色状态，由 demo 作为调用方自行保存，供 005 的 `AcceptPayment` 复核使用——SDK 不保存它。买方侧则用 `bitfs.VerifySignedContentDeliveryAt` 在不产生付款的前提下验证 004。

004 的签名对象是三字段确定性 CBOR delivery terms，其中 `refund_template_txid` 是费用池统一关联 ID，卖方签名自然覆盖它：

```text
ContentDeliveryTerms = [
    refund_template_txid,             // 与 003 条款中的字段一致
    payment_authorization_hash, // 003 条款规范编码的 SHA-256
    content_bytes               // 交付的 seed/block 原文
]
SignedContentDelivery = [4, terms_cbor, seller_signature]
```

标准输出的 `SIGNED_CONTENT_DELIVERY_HEX` 是要传给买家的交付报文。调试输出会显示 delivery terms 中已由卖家签名覆盖的 `refund_template_txid`、它与 fixture 费用池关联 ID 的一致性、请求 hash、内容引用、交付内容 hash、内容长度、价格、卖家签名以及验证结果。

验证成功只说明“卖家交付的内容对应这个请求且签名有效”。买家还需要携带同一套显式状态调用 `AcceptDelivery`，然后再进入累计付款步骤。
