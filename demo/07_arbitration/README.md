# 007：仲裁付款

这一步演示卖家认为自己已经交付内容，但买家没有完成付款时，如何把买家的付款授权交给仲裁人：卖方签署紧凑 Claim 证据构造 exact Kind 8，仲裁方先完整验证（应用在此持久化托管证据），再独立重建并签署四元 Kind 9 回执响应，最后卖方验证回执、补签并合并完整交易。

角色 workflow 只持有受约束 Signer。开池证据、签名的 003 授权、本方已发 004 与显式 `Facts{Now, BlockHeight}` 全部由 fixture（调用方应用）显式持有并传入；本例中卖家在买方未产出付款凭证的情况下，直接从 003 授权与已发交付构造仲裁证据。

运行：

```sh
go run ./demo/07_arbitration/01_arbitrate_payment
```

核心调用顺序是：

```go
// 卖方：从本地池 checkpoint、exact 已签 003 与本方发出的 exact Kind 6
// 构造 Claim 证据并签署，返回待发送 exact Kind 8 Artifact。
kind8Artifact, err := sellerWorkflow.PrepareArbitration(ctx, facts,
    seller.ArbitrationCommand{
        Pool:        sellerPoolCheckpoint,
        Request:     signedRequest,   // exact 已签 003
        DeliveryRaw: rawKind6,        // 本方已发出的交付 bytes
    })
rawKind8 := kind8Artifact.Bytes() // 应用先持久化 exact Kind 8 再发送

// 应用计费策略：对 exact len(ContentPayloadsCBOR) 用整数公式计价。
fee := protocol.Satoshis(demoFeePolicy(len(deliveryDTO.ContentPayloadsCBOR)))

// 仲裁方第一阶段：完整验证但绝不签名。需要 Facts.Now（deadline 判断）
// 与 Facts.BlockHeight（退款模板门禁）。
prepared, err := arbiterWorkflow.PrepareArbitration(ctx, facts, rawKind8, fee)

// 应用在此原子持久化托管证据：exact request 字节、Claim ID、冻结费用与
// payload bundle；只追加、不覆盖。
persist(custodyKey(prepared.ArbitrationClaimID()), prepared)

// 仲裁方第二阶段：先持久化后的签名步骤。基于冻结的 exact Kind 8 字节独立
// 重建交易与 digest，重新比对 Claim ID、费用、角色与 deadline 后按固定顺序
// 签名（先交易签名，再编码回执，最后统一消息签名）。
kind9Artifact, err := arbiterWorkflow.SignPreparedArbitration(ctx, facts, prepared)
rawKind9 := kind9Artifact.Bytes() // 签名后把 exact canonical Kind 9 追加到同一记录

// 卖方：从 exact Kind 8/9 完整验证托管收款路径，补签并合并完整交易。
signed, err := sellerWorkflow.CompleteArbitratedPayment(ctx, facts,
    seller.ArbitratedPaymentCommand{
        RequestRaw:            rawKind8,
        ResponseRaw:           rawKind9,
        DeliveryPayloadsCBOR:  savedPayloadBundleCBOR, // 可选；提供时逐字节比对
    })
broadcast(signed.RawTx()) // 是否广播由应用决定
```

007 响应是四元结构，内层回执固定为三元：

```text
ArbitrationResponse = [1, 9, ReceiptCBOR, ArbiterReceiptSignature]
ArbitrationReceipt  = [ArbitrationClaimID, ArbiterAmountSatoshis, ArbiterPaymentTransactionSignature]
ArbitrationClaimID  = SHA-256(exact ClaimCBOR)
```

仲裁请求不携带开池证明、资金交易、费率、previous state、candidate raw 或 Seller transaction signature；响应也不携带任何 raw transaction。仲裁方验证 Buyer 对精确 terms 的签名、严格角色脚本、RefundTx ID 绑定、payload 数量/顺序/hash 与 canonical CBOR，再从 Claim 独立构造按明确费用付费的 unsigned payment：`output[0]` 为 Buyer 余额、`output[1]` 为 Buyer 授权的 Seller 绝对金额、`output[2]` 为正的仲裁费。

计费属于应用策略：demo 用 `baseFeeSat + ceil(payloadCBORBytes / 1024) * satPerKiB` 的整数阶梯公式对 exact `len(ContentPayloadsCBOR)` 计费，再把金额传给 `arbiter.PrepareArbitration`。SDK 不读取环境变量、不访问报价服务、也不按 payload 长度自行选择费率。

应用必须在 `PrepareArbitration` 与 `SignPreparedArbitration` 之间原子持久化托管记录（收到的原始 Kind 8 字节——它同时是 payload bundle 的唯一真值、Claim ID、冻结费用）；签名后只更新同一记录的响应字段，绝不整体覆盖——请求字节、Claim ID 与费用必须保持原样，供审计、恢复与幂等重发使用。签名后还要保存 exact canonical Kind 9 bytes。重放以 exact 字节为门槛，不能只看 Claim ID：只有 Claim ID 与 exact Kind 8 字节完全相同才直接重发保存的字节，不重新计价、不重新签名；同 ID 不同 exact Claim 属于 hash collision 报警；exact Claim 相同但外层签名或 payload 不同时，先用已冻结费用完整验证（无效变体按证据错误拒绝，完全有效变体才是重复证据冲突）；不同 Claim ID 建立独立记录。仲裁方先签交易签名并自验，再编码回执，最后做普通消息签名并自验；卖方收到响应后独立重算 Claim ID、验证回执签名与交易签名、本地重建同一笔交易并合并。

生产服务必须在计价和 `PrepareArbitration` 之前完成链上 UTXO 前置检查，SDK 不查节点：

```text
wire.ParseAs(wire.ArbitrationRequest, rawKind8)
→ 验证 Claim 和 evidence（arbiter.PrepareArbitration 内部完成）
→ 查询并验证链上 UTXO（outpoint 存在、金额与 Claim 一致、script 与池锁一致、
   已确认且未花费）
→ 计算仲裁费
→ arbiter.PrepareArbitration
→ 持久化准备态（exact request、Claim ID、冻结费用、payload bundle）
→ arbiter.SignPreparedArbitration
→ 原子持久化 Kind 9
→ 返回响应
```

UTXO 查询失败、超时或状态不确定时必须拒绝签名，不得降级继续；本 demo 不查询 UTXO、不广播交易，也不代表交易已上链。
