# 005：累计付款

这一步把 004 的交付确认转换成费用池中的一次累计付款。买家先验证并接受交付，卖家再接受付款更新。

运行：

```sh
go run ./demo/05_cumulative_payment/01_accept_payment
```

核心调用顺序是：

```text
delivery = seller.DeliverRequestedContent(request)
paymentUpdate = buyer.AcceptDelivery(delivery)
seller.AcceptPayment(paymentUpdate)
```

可以把付款更新理解为：

```text
payment = PoolPayment{
    SpendTxID:       poolSpendTxID,
    Sequence:        request.Sequence,
    PaidAmount:      previousPaid + request.Price,
    DeliveryHash:    delivery.Hash(),
    BuyerSignature:  Sign(paymentState, buyerPrivateKey),
}
```

卖家接受时会检查付款更新属于正确的费用池、序号递增、累计金额不倒退、交付 hash 和请求匹配，然后补上卖家签名并保存新的累计状态。demo 的标准输出包含 `PAYMENT_UPDATE_HEX`、买家签名、卖家签名、累计金额和接受后的状态。

这一步仍然使用内存模拟 backend；输出的交易/签名 hex 用于观察协议数据，不代表已经广播到链上。
