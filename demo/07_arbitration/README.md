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
    opening, signedRequest, delivery, blockHeight)
prepared = arbiter.PreparePayment(arbitrationRequest, blockHeight)
persist(prepared.RequestCommitment(), prepared.UnsignedStateTxHash())
arbitrationResponse = arbiter.SignPreparedPayment(prepared)
signed = seller.CompleteArbitratedPayment(
    arbitrationRequest, arbitrationResponse, blockHeight)
```

仲裁请求可以理解为：

```text
ArbitrationRequest{
    ClaimCBOR:              [pool amount, pool script, RefundTx, 003 terms, Buyer sig],
    SellerClaimSignature:   SignMessage([4, 8, ClaimCBOR]),
    ContentPayloadsCBOR:    exact validated 004 payload bundle,
}
```

007 请求不携带 OpeningProof、FundingTx、费率、previous state、candidate raw 或 Seller transaction signature。仲裁人验证 Buyer 对精确 terms 的签名、严格角色脚本、RefundTx ID 绑定、payload 数量/顺序/hash 与 canonical CBOR，再从 Claim 独立构造 unsigned payment。应用必须在 `PreparePayment` 与 `SignPreparedPayment` 之间持久化托管记录；仲裁人分别签署 Result 和交易，卖方收到响应后重新构造并合并。保存与广播同样是调用方职责，SDK 不提交任何内容。

调试输出会显示授权 hash、交付证明与候选交易的字节数、仲裁请求和响应 hex、仲裁人公钥以及双方签名。
