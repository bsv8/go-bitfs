# 003：买家构造批量内容授权

这一步回答“买家需要某组内容时，应该如何请求”。买家使用已经开启的费用池和已验收的报价，为一个**有序内容 hash 批次**签署一条 003 授权：一个付款序号授权一组内容 hash，价格逐项计算后安全累加。

角色 workflow 只持有受约束 Signer。报价（`VerifiedQuote`）、池 checkpoint 和内容哈希批次都由 fixture（调用方应用）显式持有并逐个传入；时间与高度来自显式 `Facts{Now, BlockHeight}`，SDK 不读取任何内部存储。

运行：

```sh
go run ./demo/03_content_request/01_build_request
```

核心调用是：

```go
result, err := buyerWorkflow.RequestContent(ctx, facts, buyer.RequestContentCommand{
    // 已验收报价与当前池 checkpoint。
    Quote: verifiedQuote,
    Pool:  buyerPoolCheckpoint,
    // 有序 hash 批次：等于报价 SeedHash 的项即 seed，其余必须是该 seed
    // 提交过的块；类型由证据推导，不由调用方声明。
    ContentHashes: [][]byte{seedHash},
    // 交付截止（UTC Unix 秒）：必须晚于 facts.Now 且不超过报价有效期。
    DeliveryDeadline: content.UnixSeconds(facts.Now.Add(30 * time.Minute).Unix()),
    // 批次包含任何块时必须提供已验证 seed 原文；纯 seed 批次可空。
    Seed: nil,
})
```

返回值是一个统一 Result，应用按“先持久化、再发送”处理：

```go
rawKind5 := result.Outbound.Bytes()   // exact Kind 5 bytes：先落盘再发送
authID := result.AuthorizationID      // 授权 typed ID = SHA-256(exact 授权文档)
checkpoint := result.Checkpoint       // 必须与 Kind 5 一同持久化：
                                      // 后续 VerifyDeliveryAndPreparePayment 与
                                      // 008 取回路径都要原样回传
```

003 条款不携带公钥或矿工费率——这些值由 `RefundTemplateTxID` 对应且不可修改的开池证据唯一确定。SDK 在签名前验证引用、聚合价格、余额与序号连续性；失败按稳定错误分类返回，例如：

```go
if err != nil {
    switch {
    case protocol.IsCode(err, protocol.CodeInsufficientBalance):
        // 聚合价格超出池余额。
    case protocol.IsCode(err, protocol.CodeStateConflict):
        // 序号陈旧：本地 checkpoint 不是最新确认状态。
    case protocol.IsCode(err, protocol.CodeExpired):
        // 报价过期或交付截止不在未来。
    }
}
```

标准输出的 `SIGNED_CONTENT_REQUEST_HEX` 就是买家要发送给卖家的 exact Kind 5 Artifact 字节。

注意：这条授权表达的是“请交付这一批内容”，不是付款交易本身。卖家验证整批请求后，下一步才会生成一个原子交付整个批次 payload 的 004。
