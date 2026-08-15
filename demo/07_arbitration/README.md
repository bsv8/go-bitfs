# 007：仲裁付款

这一步演示卖家认为自己已经交付内容，但买家没有完成付款时，如何把买家的付款授权交给仲裁人，由仲裁人签署付款并提交。

运行：

```sh
go run ./demo/07_arbitration/01_arbitrate_payment
```

核心调用顺序是：

```text
request = buyer.RequestContent(...)
seller.DeliverRequestedContent(request)
arbitrationRequest = seller.BuildArbitrationRequestFromAuthorization(request)
arbitrationResponse = arbiter.SignPayment(arbitrationRequest)
seller.SubmitArbitratedPayment(arbitrationResponse)
```

仲裁请求可以理解为：

```text
ArbitrationRequest{
    PaymentAuthorization: buyerAuthorization,
    DeliveryProof:        sellerDeliveryProof,
    SpendTxID:             poolSpendTxID,
    SellerPubKey:          seller.PublicKey,
    ArbiterPubKey:         arbiter.PublicKey,
}
```

仲裁人的职责是验证授权、费用池和交付证明，在授权金额范围内签署付款。它不重新定价、不读取文件内容，也不凭空构造一笔替代买家授权的付款。卖家拿到仲裁签名后，仍要验证响应并通过 `SubmitArbitratedPayment` 提交。

调试输出会显示授权 hash、交付证明 hash、仲裁请求和响应 hex、仲裁人公钥、双方签名以及模拟提交结果。
