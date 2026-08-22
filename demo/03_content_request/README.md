# 003：买家构造内容请求

这一步回答“买家需要某个文件时，应该如何 build 报文”。买家使用已经开启的费用池和报价条款，为指定的内容引用生成 `SignedContentRequest`。

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
        Content:          bitfs.ContentRef{Type: bitfs.ContentSeed, Hash: seedHash},
        ContentSize:      1,
        DeliveryDeadline: bitfs.UnixSeconds(now.Add(30 * time.Minute).Unix()),
    },
    now)
```

伪代码表示为：

```text
sequence = previousPayment.PaymentSequence + 1
price    = quote.SeedPriceSat * ContentSize
request  = ContentRequest{
    QuoteTermsHash: QuoteTermsHash,
    RefundTemplateTxID:   RefundTemplateTxID,
    Sequence:       sequence,
    ContentRef:     ContentRef,
    ContentSize:    ContentSize,
    Price:          price,
    Deadline:       Deadline,
    BuyerPubKey:    buyer.PublicKey,
}
signedRequest, err := buyer.BuildContentRequest(...) // SDK 用构造时传入的私钥签名
```

标准输出的 `SIGNED_CONTENT_REQUEST_HEX` 就是买家要发送给卖家的需求报文。003 条款中的 `refund_template_txid` 是费用池统一关联 ID，Buyer 签名覆盖该字段。调试输出会把 terms hash、费用池关联 ID、内容引用、序号、大小、价格、截止时间、买家公钥、请求 hash 和买家签名逐项打印出来。

注意：这个请求表达的是“请交付这个内容”，不是付款交易本身。卖家验证请求后，下一步才会生成内容交付报文。
