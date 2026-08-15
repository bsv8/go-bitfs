# 002：开启费用池

这一步把 001 的报价转换成可以进行内容交付和累计付款的费用池状态。买家和卖家先交换并签名退款交易，然后买家交付 funding transaction，卖家验证并接受它。

运行：

```sh
go run ./demo/02_pool_opening/01_run_pool_opening
```

核心调用顺序是：

```text
buyer.PreparePoolOpening(quote)
    -> RefundPresignRequest
seller.PresignPoolOpening(request)
    -> RefundPresignResponse
buyer.AcceptRefundPresign(response)
    -> 保存买家退款签名
buyer.BuildFundingTxDelivery()
    -> FundingTxDelivery
seller.AcceptPoolFunding(delivery)
    -> PoolState.Open = true
```

输出中的 `OPENING_PROOF_HEX` 是买家确认卖家已经预签退款交易后的证明，`FUNDING_TX_HEX` 是买家交付给卖家的 funding transaction，`SPEND_TX_ID_HEX` 是后续花费这个池子时要引用的交易 ID。

这里使用 demo 的内存 backend，只模拟交易存在和确认状态，不广播真实交易。重点是观察签名边界和状态转换：卖家不能在没有有效退款预签名的情况下接受资金，买家也要先保存退款签名再交付 funding transaction。
