# 003：买家构造批量内容授权

这一步回答“买家需要某组内容时，应该如何 build 报文”。买家使用已经开启的费用池和报价条款，为一个**有序内容 hash 批次**生成一条 `SignedContentRequest`：一个付款序号授权一组内容 hash，价格逐项计算后安全累加。

go-bitfs SDK 无状态：workflow 只持有买家官方 BSV 私钥。报价、开池证据和最新付款状态都由 fixture（调用方应用）显式持有并逐个传入；SDK 在操作入口自取一次 UTC，不读取任何内部存储。

运行：

```sh
go run ./demo/03_content_request/01_build_request
```

核心调用是：

```go
request, err := buyerWorkflow.BuildContentRequest(ctx,
    quote, opening, previousPayment,
    buyer.ContentRequestInput{
        // 有序 hash 批次：等于报价 SeedHash 的项即 seed，其余必须是该 seed
        // 提交过的块；类型由证据推导，不由调用方声明。
        ContentHashes:    [][]byte{seedHash},
        DeliveryDeadline: bitfs.UnixSeconds(now.Add(30 * time.Minute).Unix()),
    })
```

伪代码表示为：

```text
hashes  = [seedHash]                      // 或 [blockHash0, blockHash1, ...]
price   = sum(priceOf(h) for h in hashes) // 逐项 checked-add，绝不回绕
terms   = [
    quote_terms_hash,                     // 选择报价（费用池由 txid 选择）
    refund_template_txid,                 // 选择费用池并恢复角色与费率
    payment_sequence,                     // 本次目标序号 = 当前已接受序号 + 1
    seller_amount_after_sat,              // 付款后卖方绝对累计金额
    content_hashes_cbor,                  // 规范子 CBOR bstr：1..64 个有序 hash
    delivery_deadline_unix,
]
request = [4, terms_cbor, buyer_signature] // Buyer 签名精确覆盖 terms_cbor
```

标准输出的 `SIGNED_CONTENT_REQUEST_HEX` 就是买家要发送给卖家的授权报文。003 条款不再重复携带公钥或矿工费率——这些值由 `refund_template_txid` 对应且不可修改的 OpeningProof 唯一确定。调试输出会把 quote hash、费用池关联 ID、有序 hash 批次、目标序号、绝对累计金额和截止时间逐项打印出来。

注意：这条授权表达的是“请交付这一批内容”，不是付款交易本身。卖家验证整批请求后，下一步才会生成一个原子交付整个批次 payload 的 004。
