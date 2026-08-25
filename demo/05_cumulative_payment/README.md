# 005：累计付款

这一步把 004 的交付确认转换成费用池中的一次累计付款。买方先全量验收交付，再生成整批唯一的最小付款凭证；卖方按授权 ID 取回原始 003、本地重建状态交易、验签后补签合并。

角色 workflow 只持有受约束 Signer。报价、池 checkpoint、003/004 exact bytes 和卖方 `DeliveryCheckpoint` 全部由 fixture（调用方应用）显式持有并传入；时间与高度来自显式 `Facts{Now, BlockHeight}`。

运行：

```sh
go run ./demo/05_cumulative_payment/01_accept_payment
```

核心调用顺序是：

```go
// 买方：验收 exact Kind 6 并产生整批唯一的 Kind 7 签名凭证。
payment, err := buyerWorkflow.VerifyDeliveryAndPreparePayment(ctx, facts,
    buyer.VerifyDeliveryCommand{
        Quote:       verifiedQuote,
        Pool:        buyerPoolCheckpoint,
        Request:     authorizationCheckpoint, // 本批次持久化的 003 checkpoint
        DeliveryRaw: rawKind6,
        Seed:        seedBytes,               // 批次包含任何块时提供
    })
// payment.Payloads 是已验证 payload（落盘由应用负责）；
// 先保存 payloads 与 Result 再发送 Kind 7：
rawKind7 := payment.Outbound.Bytes()

// 卖方：按 PaymentAuthorizationID 取回原始签名 003 后完成付款。
authorization := app.LookupPaymentAuthorization(paymentID) // 应用自己的索引
completed, err := sellerWorkflow.CompletePayment(ctx, facts, seller.PaymentCommand{
    Pool:       sellerPoolCheckpoint,
    Request:    authorization,          // 原始签名 003
    UpdateRaw:  rawKind7,
    Checkpoint: deliveryCheckpoint,     // 生成 004 时保存的 DeliveryCheckpoint
})
rawTx := completed.Transaction.RawTx() // 完整付款交易；是否广播由应用决定
nextPool := completed.NextPool         // 卖方推进后的本地 checkpoint
```

可以把最小付款凭证理解为 wire Kind 7：

```text
credential = [1, 7,
    payment_authorization_id,              // SHA-256(exact payment_authorization_cbor)，应用查找键
    buyer_payment_transaction_signature,   // 对本地重建状态交易 sighash 的签名
]
```

005 不携带费用池 ID 或未签名交易：wire 只有授权 ID 和买方交易签名。交易在双方本地用同一组证据（开池证明 + previous 付款状态 + 003 目标序号/金额）确定性重建；卖方验证买方签名确实覆盖这笔精确重建的交易、交叉核对 `DeliveryCheckpoint` 与原始 003 后补签并合并，返回完整付款交易和新的池 checkpoint。demo 中双方随后把各自 checkpoint 推进到同一确认状态（fixture 用 canonical opening proof + 完整付款 raw tx 经 `buyer.RestorePoolCheckpoint` 全量重验恢复）。

`payment_authorization_id` 是内容寻址键而不是池 ID：同一费用池可产生多个不同授权 ID，找不到对应原始 003 时必须拒绝或请求重发，不允许扫描池或按连接猜池。同一费用池的 005 必须由应用按池串行化处理。

SDK 不广播任何交易；输出的交易/签名 hex 用于观察协议数据，不代表已经上链。广播与链上对账由调用方负责。
