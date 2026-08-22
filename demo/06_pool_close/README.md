# 006：关闭费用池

这一步演示在双方已经完成一次内容交付和累计付款后，买家发起协商关闭，卖家签名，买家验证出最终可广播的关闭交易。

go-bitfs SDK 无状态：workflow 只持有官方 BSV 私钥。开池证据、基准付款状态、目标金额和区块高度由 fixture（调用方应用）显式持有并传入；SDK 自取 UTC，不判断业务最新状态或目标金额是否符合订单。demo 先完成一次普通 005 付款作为前提条件：应用先按授权哈希查回原始签名 003，卖家验证后本地重建状态交易并合并双方签名；合并后的付款被当作新的最新状态保存在调用方侧。006 的关闭交易构造与 005 的状态交易重建规则无关，关闭仍走独立的 final-sequence API。

运行：

```sh
go run ./demo/06_pool_close/01_close_pool
```

核心调用顺序是：

```text
blockHeight = uint32(...)        // 区块高度由调用方提供

unsigned, buyerSignature =
    buyer.BuildImmediateClose(opening, latestPayment, facts)
closed = seller.SignImmediateClose(opening, latestPayment,
                                   unsigned, buyerSignature, facts)
completed = buyer.CompleteImmediateClose(opening, closed)
    -> 已完整签名的关闭交易，等待调用方广播
```

关闭交易会把当前累计付款状态作为最终分配依据。与超时退款路径不同，这是双方已经同意当前余额后的 negotiated close。调试输出会显示费用池引用、关闭前累计金额、未签名交易、买家与卖家签名以及最终交易 hex 和交易 ID；demo 不会提交这笔交易，广播是调用方的职责。

伪代码：

```text
closeTx = BuildCloseTx(pool, latestPayment)
closeTx = seller.Sign(closeTx, sellerPrivateKey)
require(VerifySellerSignature(closeTx))
broadcast(closeTx)   // 调用方职责
```
