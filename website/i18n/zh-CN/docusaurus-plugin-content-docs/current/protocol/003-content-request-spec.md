---
id: 003-content-request-spec
title: 003 · 内容获取请求规范
---

# 003 · 内容获取请求规范

BitFS v1 的最终 wire 形态固定且唯一；旧版形态（重复公钥、费率、base/after 双序号、内容类型、单哈希）一律拒绝。`protocol.WireVersion = 1` 内不存在兼容 decoder，也不允许 presence guessing。

```text
kind-5-content-request = [
    1,                                   ; wire-version，由 encoder 固定注入
    5,                                   ; wire kind
    payment_authorization_cbor,
    buyer_payment_authorization_signature
]

payment_authorization_cbor = deterministic-CBOR([
    file_quote_terms_id,           ; bstr .size 32 = SHA-256(exact 报价条款 cbor)
    refund_template_txid,          ; bstr .size 32；按交易协议 TxID 算法派生
    payment_sequence,              ; uint .le 4294967294：目标序号 = 前态 + 1
    seller_amount_after_satoshis,  ; uint：卖方绝对累计金额
    content_hashes_cbor,           ; bstr .cbor [1*64 sha256]，有序且不重复
    delivery_deadline_unix_seconds ; int > 0，不超过报价有效期
])

buyer_payment_authorization_signature =
    SignWireDocument(buyer_key, 1, 5, payment_authorization_cbor)

payment_authorization_id = SHA-256(payment_authorization_cbor)
```

认证文档不携带外层版本和 Kind，也不携带公钥与费率；身份与费率从绑定 `refund_template_txid` 的 OpeningProof 恢复。`SignWireDocument` 签署类型化输入 `["bitfs/wire-signature", 1, 5, payment_authorization_cbor]`，版本和 Kind 与 exact 文档字节一起纳入认证。

`payment_authorization_id` 是后续 004、005、007 的 `PaymentAuthorizationID`；它是指向保存的原始签名请求的内容寻址查找键，永远无法解码出池身份、序号或金额。授权同时签入目标 `PaymentSequence` 和绝对累计卖方金额，双方随后据此重建 005 状态交易。007 中卖方使用保存的 003 与已验证的 004 payload bundle 形成 Claim，仲裁者从 Claim 的 source context 独立重建交易。wire 不携带可协商仲裁金额；正数仲裁费由调用应用在提交 007 时显式决定。
