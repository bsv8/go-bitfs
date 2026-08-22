# 007：仲裁付款

这一步演示卖家认为自己已经交付内容，但买家没有完成付款时，如何把买家的付款授权交给仲裁人，由仲裁人签署付款。

go-bitfs SDK 无状态：workflow 只持有官方 BSV 私钥。开池证据、基准付款状态、签名的 003 授权和区块高度全部由 fixture（调用方应用）显式持有并传入；SDK 在操作入口自行读取一次 UTC；本例中卖家在买方未产出 005 的情况下，直接从 003 授权构造仲裁证据。

运行：

```sh
go run ./demo/07_arbitration/01_arbitrate_payment
```

核心调用顺序是：

```text
arbitrationRequest = seller.BuildArbitrationRequest(
    opening, signedRequest, latestPayment, facts)
arbitrationResponse = arbiter.SignPayment(arbitrationRequest)
signed = seller.CompleteArbitratedPayment(
    opening, latestPayment, arbitrationRequest, arbitrationResponse, facts)
```

仲裁请求可以理解为：

```text
ArbitrationRequest{
    PoolOpeningProofCBOR:       开池证据规范 CBOR,
    PaymentAuthorizationCBOR:   买方 003 授权条款与签名,
    UnsignedStateTxRaw:         卖方构造的候选付款交易,
    SellerTransactionSignature: 卖方候选签名,
    RefundTemplateTxID:               poolRefundTemplateTxID,
}
```

007 请求和响应都显式携带同一 `RefundTemplateTxID` 关联 ID。仲裁人的职责是从 OpeningProof 恢复角色与费率，核对 request hash、开池证据派生的 RefundTemplateTxID、003 池绑定与买方签名以及 unsigned state 解析出的目标序号/金额全部一致后，在授权金额范围内签署付款；`arbitration.SignPayment` 验证证据后只添加仲裁方签名。它不重新定价、不读取文件内容，也不凭空构造一笔替代买家授权的付款。卖家收到响应时还必须把响应 hash 与原 007 request 再绑定，再通过 `CompleteArbitratedPayment` 合并出完整的已签付款交易；保存与广播这笔交易同样是调用方的职责，SDK 不提交任何内容。

调试输出会显示授权 hash、交付证明与候选交易的字节数、仲裁请求和响应 hex、仲裁人公钥以及双方签名。
