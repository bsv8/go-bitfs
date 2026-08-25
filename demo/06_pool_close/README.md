# 006：关闭费用池

这一步演示在双方已经完成一次内容交付和累计付款后，买家发起协商关闭，卖家签名，买家验证出最终可广播的关闭交易。

角色 workflow 只持有受约束 Signer。开池证据、基准付款状态和目标金额由 fixture（调用方应用）显式持有并传入；时间与高度来自显式 `Facts{Now, BlockHeight}`。demo 先完成一轮普通付款作为前提条件：卖方合并双方签名后返回完整付款交易和新的池 checkpoint，fixture 把它同步为双方的共享确认状态。006 的关闭交易构造与 005 的状态交易重建规则无关，关闭走独立的 final-sequence API。

运行：

```sh
go run ./demo/06_pool_close/01_close_pool
```

核心调用顺序是：

```go
latest := f.LatestPayment // 调用方保存的最新已确认付款状态

// 买方：从调用方选定的基准状态构造未签名关闭 candidate 与买方分离签名。
closePrep, err := buyerWorkflow.PrepareClose(ctx, facts, buyer.PrepareCloseCommand{
    Pool:                       buyerPoolCheckpoint,
    Base:                       latest, // SDK 不声称 base 是业务最新
    TargetSellerAmountSatoshis: targetAmount,
})
// closePrep.Unsigned + closePrep.BuyerSignature 都要先持久化再发送给卖方。

// 卖方：验证 candidate 结构、金额边界与买方签名后补签并合并；不广播。
closed, err := sellerWorkflow.CompleteClose(ctx, facts, seller.CloseCommand{
    Pool:           sellerPoolCheckpoint,
    Unsigned:       closePrep.Unsigned,
    BuyerSignature: closePrep.BuyerSignature,
})

// 买方：复核完整最终交易在给定 opening 下密码学、结构与交易关系全部正确。
verified, err := buyerWorkflow.VerifyCompletedClose(ctx, buyer.VerifyCloseCommand{
    Pool:  buyerPoolCheckpoint,
    Close: closed,
})
finalTx := verified.RawTx() // 是否广播由调用方决定
```

关闭交易把当前累计付款状态作为最终分配依据。与超时退款路径不同，这是双方已经同意当前余额后的 negotiated close。调试输出会显示费用池引用、关闭前累计金额、未签名交易、买家签名以及最终交易 hex 和交易 ID；demo 不会提交这笔交易，广播是调用方的职责。

超时退款路径同样是显式事实驱动的纯计算：

```go
// 只有 facts 判定退款锁定已到期才会成功；未到期按 CodeNotMatured 拒绝。
refund, err := buyerWorkflow.BuildMaturedRefund(ctx, facts, buyerPoolCheckpoint)
broadcast(refund.RawTx()) // 调用方职责
```
