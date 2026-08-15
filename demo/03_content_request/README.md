# 003：买家构造内容请求

这一步回答“买家需要某个文件时，应该如何 build 报文”。买家使用已经开启的费用池和报价条款，为指定的内容引用生成 `SignedContentRequest`。

运行：

```sh
go run ./demo/03_content_request/01_build_request
```

核心调用是：

```go
request, err := buyerWorkflow.RequestContent(ctx, buyer.RequestContentParams{
    QuoteTermsHash: quote.TermsHash,
    SpendTxID:      poolSpendTxID,
    ContentRef:     quote.SeedHash, // demo 请求 seed
    ContentSize:    1,
    Deadline:       now.Add(1 * time.Hour),
})
```

伪代码表示为：

```text
sequence = pool.NextSequence()
price = quote.PricePerSeed * ContentSize
request = ContentRequest{
    QuoteTermsHash: QuoteTermsHash,
    SpendTxID:      SpendTxID,
    Sequence:       sequence,
    ContentRef:     ContentRef,
    ContentSize:    ContentSize,
    Price:          price,
    Deadline:       Deadline,
    BuyerPubKey:    buyer.PublicKey,
}
signedRequest = Sign(request, buyerPrivateKey)
```

标准输出的 `SIGNED_CONTENT_REQUEST_HEX` 就是买家要发送给卖家的需求报文。调试输出会把 terms hash、费用池引用、内容引用、序号、大小、价格、截止时间、买家公钥、请求 hash 和买家签名逐项打印出来。

注意：这个请求表达的是“请交付这个内容”，不是付款交易本身。卖家验证请求后，下一步才会生成内容交付报文。
