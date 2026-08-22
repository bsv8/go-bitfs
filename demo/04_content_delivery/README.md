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

卖家的 `BuildContentDelivery` 先完整验证原始 003（池绑定、买方签名、报价、时间），重新计算授权哈希，解码 003 已提交的有序 hash，然后逐项验证 payload 数量、顺序、SHA-256、seed/block 归属与协议期望长度，并重算聚合价格与目标序号。全部通过后才对**精确 32 字节的 `PaymentAuthorizationHash` 做裸消息签名**，返回交付报文和一个记录目标的 `ContentDeliveryState`（费用池 ID、授权哈希、目标序号、绝对累计卖方金额）。该 state 由 demo 作为调用方自行保存，供 005 的 `AcceptPayment` 复核使用——SDK 不保存它。

004 是四元确定性 CBOR 外壳，payload 放在签名字段之后，通过 003 已提交的有序 hash 间接绑定：

```text
SignedContentDelivery = [
    4,
    payment_authorization_hash,   // SHA-256(003 terms_cbor)，唯一签名对象
    seller_payment_authorization_hash_signature,
    content_payloads_cbor         // 规范子 CBOR bstr，顺序与 003 hashes 一一对应
]
```

绑定链完整成立：BuyerSignature → 003 TermsCBOR → ordered ContentHashesCBOR + 池 + 序号 + 金额；PaymentAuthorizationHash = SHA-256(003 TermsCBOR)；SellerSignature → PaymentAuthorizationHash；ContentPayloadsCBOR[i] 的 SHA-256 必须等于 ContentHashesCBOR[i]。

买方应用按 `PaymentAuthorizationHash` 路由 004 到本地保存的原始 003；本地找不到时只能暂存或请求对端重发 003，不能从 payload 猜测订单或费用池。

标准输出的 `SIGNED_CONTENT_DELIVERY_HEX` 是要传给买家的交付报文。调试输出会显示授权哈希、裸哈希签名的十六进制、payload 批次的条数与大小等。

验证成功只说明“卖家对这条付款授权给出了可验证的整批 payload”。买家还需要调用 `AcceptDelivery` 全量验证后生成唯一的 005，再进入累计付款步骤。
