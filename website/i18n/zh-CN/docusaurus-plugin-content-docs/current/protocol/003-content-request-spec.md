---
id: 003-content-request-spec
title: 003 · v4 内容获取请求规范
---

# 003 · v4 内容获取请求规范

v4 的最终 wire 形态固定且唯一；切换前的旧 v4 形态（重复公钥、费率、base/after 双序号、内容类型、单哈希）一律拒绝。

```text
SignedContentRequest = [4, terms_cbor, buyer_signature]

terms_cbor = deterministic-CBOR([
    quote_terms_hash,        ; bstr .size 32
    refund_template_txid,    ; bstr .size 32
    payment_sequence,        ; uint：目标序号 = 前态 + 1，且 <= 0xfffffffe
    seller_amount_after_sat, ; uint：卖方绝对累计金额
    content_hashes_cbor,     ; bstr .cbor [1*64 content-hash]，有序且不重复
    delivery_deadline_unix   ; int > 0，不超过报价有效期
])

buyer_signature = SignMessage(buyer_key, terms_cbor)
payment_authorization_hash = SHA-256(terms_cbor)
```

外壳版本 `4` 不进入买方签名。条款没有内层版本字段，也不携带公钥与费率；身份与费率从绑定 `refund_template_txid` 的 OpeningProof 恢复。授权哈希作为后续 004、005、007 的 `PaymentAuthorizationHash`。当前版本不携带可协商仲裁金额，构建层始终使用 `ArbiterAmount = 0`。
