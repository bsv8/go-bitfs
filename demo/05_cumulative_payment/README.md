# 005：累计付款

这一步把 004 的交付确认转换成费用池中的一次累计付款。买家先验证并接受交付，卖家再接受付款更新。

go-bitfs SDK 无状态：workflow 只持有官方 BSV 私钥。报价、开池证据、最新付款状态、003/004 报文和 004 返回的 `ContentDeliveryState` 全部由 fixture（调用方应用）显式持有并传入；当前时间由 SDK 在每次操作入口读取一次 UTC，区块高度由调用方显式提供。

运行：

```sh
go run ./demo/05_cumulative_payment/01_accept_payment
```

核心调用顺序是：

```text
delivery, deliveryState = seller.BuildContentDelivery(
    quote, opening, previousPayment, request,
    ContentDeliveryInput{Content: seedBytes}, now)
verified = buyer.AcceptDelivery(quote, opening, previousPayment,
                                request, delivery, now)
signed   = seller.AcceptPayment(opening, latestPayment, deliveryState,
                                verified.Update, facts)
```

可以把付款更新理解为：

```text
payment = PoolPayment{
    RefundTemplateTxID:    poolRefundTemplateTxID,
    Sequence:        request.Sequence,
    PaidAmount:      previousPaid + request.Price,
    DeliveryHash:    delivery.Hash(),
    BuyerSignature:  Sign(paymentState, buyerPrivateKey),
}
```

005 显式携带 `refund_template_txid` 作为费用池统一关联 ID。卖家的 `AcceptPayment` 以调用方传入的 OpeningProof、最新付款状态和 004 的 `ContentDeliveryState` 为唯一依据，检查该 hash 与各证据派生值一致、序号递增、累计金额不倒退、交付与请求匹配，然后补上卖家签名，返回完整的已签付款交易和新的累计状态；保存这份新状态仍是调用方的职责。接收前后该 hash 保持同一池关联。

SDK 不广播任何交易；输出的交易/签名 hex 用于观察协议数据，不代表已经上链。广播与链上对账由调用方负责。
