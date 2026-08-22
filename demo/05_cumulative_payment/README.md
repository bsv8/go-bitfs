# 005：累计付款

这一步把 004 的交付确认转换成费用池中的一次累计付款。买家先验证并接受交付，再生成最小付款凭证；卖家按授权哈希取回原始 003、本地重建状态交易、验签后补签合并。

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
authorization = fixture.LookupPaymentAuthorization(   // 应用按授权哈希查回原始 003
    verified.Update.PaymentAuthorizationHash)
signed   = seller.AcceptPayment(opening, latestPayment, authorization,
                                deliveryState, verified.Update, facts)
```

可以把最小付款凭证理解为：

```text
credential = PaymentUpdate{
    PaymentAuthorizationHash:  SHA256(request.TermsCBOR), // 应用查找键，不可解码
    BuyerSignature:            Sign(rebuiltStateTx, buyerPrivateKey),
}
rebuiltStateTx = BuildPaymentUpdate(openingProof, previousPayment,
                                    request.Sequence, request.SellerAmountAfterSat)
```

005 不再携带费用池 ID 或未签名交易：wire 只有授权哈希和买方交易签名。交易在双方本地用同一组证据（OpeningProof + previous PaymentState + 003 目标序号/金额）经唯一的 `BuildPaymentUpdate` 确定性重建；卖家用固定 verifier 对重建出的精确交易验证买方签名，交叉核对 `ContentDeliveryState` 与原始 003 后补签并合并，返回完整的已签付款交易和新的累计状态；保存这份新状态仍是调用方的职责。

授权哈希是内容寻址键而不是池 ID：同一费用池可产生多个不同授权哈希，找不到对应原始 003 时必须拒绝或请求重发，不允许扫描池或按连接猜池。同一费用池的 005 必须由应用按池串行化处理。

SDK 不广播任何交易；输出的交易/签名 hex 用于观察协议数据，不代表已经上链。广播与链上对账由调用方负责。
