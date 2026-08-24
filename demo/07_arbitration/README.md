# 007：仲裁付款

这一步演示卖家认为自己已经交付内容，但买家没有完成付款时，如何把买家的付款授权交给仲裁人，由仲裁人决定一笔正的仲裁费、签署付费的三输出状态交易，并返回四元 Kind 9 回执响应。

go-bitfs SDK 无状态：workflow 只持有官方 BSV 私钥。开池证据、基准付款状态、签名的 003 授权和区块高度全部由 fixture（调用方应用）显式持有并传入；SDK 在操作入口自行读取一次 UTC；本例中卖家在买方未产出 005 的情况下，直接从 003 授权构造仲裁证据。

运行：

```sh
go run ./demo/07_arbitration/01_arbitrate_payment
```

核心调用顺序是：

```text
arbitrationRequest = seller.BuildArbitrationRequest(
    opening, signedRequest, delivery, blockHeight)
arbiterAmountSat = demoFeePolicy(len(arbitrationRequest.ContentPayloadsCBOR))
prepared = arbiter.PreparePayment(arbitrationRequest, blockHeight, arbiterAmountSat)
persist(exact request, payload bundle, Claim ID, frozen fee)
arbitrationResponse = arbiter.SignPreparedPayment(prepared)
persist(exact canonical response bytes)   // 发送失败时原样重发
signed = seller.CompleteArbitratedPayment(
    arbitrationRequest, arbitrationResponse, blockHeight)
```

仲裁请求可以理解为：

```text
ArbitrationRequest{
    ClaimCBOR:              [pool amount, pool script, RefundTx, 003 terms, Buyer sig],
    SellerArbitrationClaimSignature: SignWireDocument(1, 8, ClaimCBOR),
    ContentPayloadsCBOR:    exact validated 004 payload bundle,
}
```

007 响应是四元结构，内层回执固定为三元：

```text
ArbitrationResponse = [1, 9, ReceiptCBOR, ArbiterReceiptSignature]
ArbitrationReceipt  = [ArbitrationClaimID, ArbiterAmountSatoshis, ArbiterPaymentTransactionSignature]
ArbitrationClaimID  = SHA-256(exact ClaimCBOR)
```

仲裁请求不携带 OpeningProof、FundingTx、费率、previous state、candidate raw 或 Seller transaction signature；响应也不携带任何 raw transaction。仲裁人验证 Buyer 对精确 terms 的签名、严格角色脚本、RefundTx ID 绑定、payload 数量/顺序/hash 与 canonical CBOR，再从 Claim 独立构造按明确费用付费的 unsigned payment：`output[0]` 为 Buyer 余额、`output[1]` 为 Buyer 授权的 Seller 绝对金额、`output[2]` 为正的仲裁费。

计费属于应用策略：demo 用 `baseFeeSat + ceil(payloadCBORBytes / 1024) * satPerKiB` 的整数阶梯公式对 exact `len(ContentPayloadsCBOR)` 计费，再把金额传给 `PreparePayment`。SDK 不读取环境变量、不访问报价服务、也不按 payload 长度自行选择费率。

应用必须在 `PreparePayment` 与 `SignPreparedPayment` 之间原子持久化托管记录（收到的原始 Kind 8 字节——它同时是 payload bundle 的唯一真值、Claim ID、冻结费用）；签名后只更新同一记录的响应字段，绝不整体覆盖——请求字节、Claim ID 与费用必须保持原样，供审计、恢复与幂等重发使用。签名后还要保存 exact canonical Kind 9 bytes。重放以 exact 字节为门槛，不能只看 Claim ID：只有 Claim ID 与 exact Kind 8 字节完全相同才直接重发保存的字节，不重新计价、不重新签名；同 ID 不同 exact Claim 属于 hash collision 报警；exact Claim 相同但外层签名或 payload 不同时，先用已冻结费用完整验证（无效变体按证据错误拒绝，完全有效变体才是重复证据冲突）；不同 Claim ID 建立独立记录。仲裁方先签交易签名并自验，再编码回执，最后通过 `SignWireDocument(1, 9, receipt_cbor)` 做普通消息签名并自验；卖方收到响应后独立重算 Claim ID、验证回执签名与交易签名、本地重建同一笔交易并合并。

生产服务必须在计价和 `PreparePayment` 之前完成链上 UTXO 前置检查，SDK 不查节点：

```text
严格解码 Kind 8
→ 验证 Claim 和 evidence
→ 查询并验证链上 UTXO（outpoint 存在、金额与 Claim 一致、script 与池锁一致、
   已确认且未花费）
→ 计算仲裁费
→ PreparePayment
→ 持久化准备态
→ SignPreparedPayment
→ 原子持久化 Kind 9
→ 返回响应
```

UTXO 查询失败、超时或状态不确定时必须拒绝签名，不得降级继续；本 demo 不查询 UTXO、不广播交易，也不代表交易已上链。
