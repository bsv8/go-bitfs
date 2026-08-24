---
id: 004-content-delivery-spec
title: 004 · 内容交付凭证规范
---

# 004 · 内容交付凭证规范

004 是 wire Kind 6：固定五元外壳，卖方签名通过统一 `SignWireDocument(1, 6, ...)` 覆盖精确 `content_delivery_cbor`。不存在单独的 DeliveryTerms 层，签名文档内没有费用池 ID 或内容哈希；payload 批次作为 attachment 传输，由所引用的付款授权间接绑定。

```text
kind-6-content-delivery = [
    1,                                    ; wire-version，由 encoder 固定注入
    6,                                    ; wire kind
    content_delivery_cbor,
    seller_content_delivery_signature,    ; SignWireDocument(1, 6, ...)
    content_payloads_cbor                 ; attachment，不直接入签
]

content_delivery_cbor = deterministic-CBOR([
    payment_authorization_id   ; bstr .size 32 = SHA-256(exact 003 payment authorization)
])

content_payloads_cbor = deterministic-CBOR([1*64 payload])
payloads[i] 与所引用 003 的哈希顺序一一对应；
每个 payload 非空且不超过一个 MasterSeed 块长。
```

payload 绑定从不依赖 presence 或信任：

```text
seller signature -> content_delivery_cbor -> payment_authorization_id
  -> payment_authorization_cbor -> ordered content_hashes_cbor
  -> SHA-256(content_payloads[i])
```

买方验收顺序：按 `PaymentAuthorizationID` 定位本地保存的原始 003；严格解码 `content_delivery_cbor` 并要求它恰好提交到该 ID；用 OpeningProof 的卖方公钥验证卖方对精确文档的统一签名；严格解码 payload 并校验数量、顺序、逐项 SHA-256、归属与期望长度；重算聚合价格、目标序号和绝对累计金额。只有每一项都成功，买方才本地构造并签署状态交易，但只发送最小 005 凭证（`payment_authorization_id` 加买方交易签名）。
