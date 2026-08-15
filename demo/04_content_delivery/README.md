# 004：卖家交付内容

这一步演示卖家收到 003 的需求后，读取内容并生成 `SignedContentDelivery`。demo 还会用协议的验证函数检查交付报文，但不会在这一步完成 005 的付款。

运行：

```sh
go run ./demo/04_content_delivery/01_deliver_content
```

核心调用是：

```text
request = buyer.RequestContent(...)
delivery = seller.DeliverRequestedContent(request)
VerifySignedContentDeliveryAt(delivery, request, now)
```

卖家交付报文大致包含：

```text
SignedContentDelivery{
    RequestHash: request.Hash(),
    ContentRef:  request.ContentRef,
    ContentSize: request.ContentSize,
    Content:     requestedBytes,
    Price:       request.Price,
    SellerSig:   Sign(deliveryTerms, sellerPrivateKey),
}
```

标准输出的 `SIGNED_CONTENT_DELIVERY_HEX` 是要传给买家的交付报文。调试输出会显示请求 hash、内容引用、交付内容 hash、内容长度、价格、卖家签名以及验证结果。

验证成功只说明“卖家交付的内容对应这个请求且签名有效”。买家还需要调用 `AcceptDelivery`，然后再进入累计付款步骤。
