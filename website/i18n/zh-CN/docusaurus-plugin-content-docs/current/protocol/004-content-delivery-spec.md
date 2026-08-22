---
id: 004-content-delivery-spec
title: 004 · v4 内容交付凭证规范
---

# 004 · v4 内容交付凭证规范

004 使用协议 major `4` 作为固定四元外壳。不存在单独的 DeliveryTerms 层，没有费用池 ID、内容哈希或进入签名结构的 payload；切换前的旧 v4 形态一律拒绝。

```text
SignedContentDelivery = [
    4,                                       ; 外壳版本，不入签
    payment_authorization_hash,              ; bstr .size 32 = SHA-256(003 terms_cbor)
    seller_payment_authorization_hash_signature,
    content_payloads_cbor                    ; bstr .cbor [1*64 content-payload]
]

seller_payment_authorization_hash_signature =
    SignMessage(seller_private_key, payment_authorization_hash)

content_payloads_cbor = deterministic-CBOR(payloads)   ; 作为 bstr 嵌入
payloads[i] 与所引用 003 的哈希顺序一一对应；
每个 payload 非空且不超过一个 MasterSeed 块长。
```

买方验收顺序：按 `PaymentAuthorizationHash` 定位本地保存的原始 003；重算并逐字节比较哈希；加载 OpeningProof 和当前 PaymentState 并重新派生池绑定；用 OpeningProof 的卖方公钥验证卖方对裸 32 字节哈希的签名；严格解码 payload 并校验数量、顺序、逐项 SHA-256、归属与期望长度；重算聚合价格、目标序号和绝对累计金额。只有每一项都成功，买方才构造并签名唯一的 005。
