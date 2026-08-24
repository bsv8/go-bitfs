# 004：卖家原子交付内容批次

这一步演示卖家收到 003 的批量授权后，读取整批内容并生成一个 `SignedContentDelivery`：一个交付包原子交付同一批 payload，全有或全无。demo 还会用 SDK 验证交付结构，但不会在这一步完成 005 付款。

go-bitfs SDK 无状态：workflow 只持有官方 BSV 私钥。003 授权、报价、开池证据、最新付款状态和内容字节（本例即 seed 原文）全部由 fixture 显式持有并传入；SDK 不保存任何中间状态。

运行：

```sh
go run ./demo/04_content_delivery/01_deliver_content
```

核心调用是：

```text
delivery, deliveryState = seller.BuildContentDelivery(
    quote, opening, previousPayment, request,
    ContentDeliveryInput{ContentPayloads: [][]byte{seedBytes}})
```

卖家的 `BuildContentDelivery` 先完整验证原始 003（池绑定、买方统一签名、报价、时间），重新计算 `PaymentAuthorizationID = SHA-256(exact payment_authorization_cbor)`，解码 003 已提交的有序 hash，然后逐项验证 payload 数量、顺序、SHA-256、seed/block 归属与协议期望长度，并重算聚合价格与目标序号。全部通过后才通过统一 helper **对精确 `content_delivery_cbor` 做 `SignWireDocument(1, 6, ...)` 签名**，返回交付报文和一个记录目标的 `ContentDeliveryState`（费用池关联 ID、授权 ID、目标序号、绝对累计卖方金额）。该 state 由 demo 作为调用方自行保存，供 005 的 `AcceptPayment` 复核使用——SDK 不保存它。

004 是 wire Kind 6 五元确定性 CBOR 外壳，payload 作为 attachment 放在签名字段之后，不直接进入签名预映像：

```text
kind-6-content-delivery = [
    1,                                    // wire-version，由 encoder 注入
    6,                                    // wire kind
    content_delivery_cbor,                // deterministic-CBOR([payment_authorization_id])
    seller_content_delivery_signature,    // SignWireDocument(1, 6, ...)
    content_payloads_cbor                 // 规范子 CBOR bstr，顺序与 003 hashes 一一对应
]
```

绑定链完整成立：SellerSignature → content_delivery_cbor → PaymentAuthorizationID → payment_authorization_cbor → ordered content_hashes_cbor + 池 + 序号 + 金额；content_payloads_cbor[i] 的 SHA-256 必须等于 content_hashes_cbor[i]。

买方应用按 `PaymentAuthorizationID` 路由 004 到本地保存的原始 003；本地找不到时只能暂存或请求对端重发 003，不能从 payload 猜测订单或费用池。

标准输出的 `SIGNED_CONTENT_DELIVERY_HEX` 是要传给买家的交付报文。调试输出会显示授权 ID、统一签名、payload 批次的条数与大小等。

验证成功只说明“卖家对这条付款授权给出了可验证的整批 payload”。买家还需要调用 `AcceptDelivery` 全量验证后生成唯一的 005，再进入累计付款步骤。
