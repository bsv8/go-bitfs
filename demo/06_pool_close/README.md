# 006：关闭费用池

这一步演示在双方已经完成一次内容交付和累计付款后，买家发起协商关闭，卖家签名，买家提交最终关闭交易。

运行：

```sh
go run ./demo/06_pool_close/01_close_pool
```

核心调用顺序是：

```text
buyer.BuildImmediateClose()
    -> unsigned close transaction
seller.SignImmediateClose(unsignedClose)
    -> seller-signed close transaction
buyer.SubmitImmediateClose(signedClose)
    -> PoolState.Closed = true
```

关闭交易会把当前累计付款状态作为最终分配依据。与超时退款路径不同，这是双方已经同意当前余额后的 negotiated close。调试输出会显示费用池引用、关闭前累计金额、未签名交易、卖家签名、最终交易 hex 和模拟提交结果。

伪代码：

```text
closeTx = BuildCloseTx(pool, latestPayment)
closeTx = seller.Sign(closeTx, sellerPrivateKey)
require(VerifySellerSignature(closeTx))
buyer.Submit(closeTx)
```
