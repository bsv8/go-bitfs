---
id: 003-content-request-spec
title: 003 · v4 内容获取请求规范
---

# 003 · v4 内容获取请求规范

003 的业务字段保持原有报价、内容和交付期限语义，编码 major 为 4。最终授权固定绑定 pool `refund_template_txid`（未签名预签名 RefundTx 哈希）、base/target sequence、Seller 绝对累计金额、整数费率及 Buyer/Seller/Arbiter 公钥。

授权哈希作为后续 004、005、007 的 `PaymentAuthorizationHash`。当前版本不携带可协商仲裁金额，构建层始终使用 `ArbiterAmount = 0`。
