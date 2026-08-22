---
id: 004-content-delivery-spec
title: 004 · v4 内容交付凭证规范
---

# 004 · v4 内容交付凭证规范

004 编码 major 为 4，携带费用池 `RefundTemplateTxID` 关联 ID，引用 003 的 `PaymentAuthorizationHash` 并携带内容字节。Seller 对确定性 CBOR 交付条款签名，其首个业务字段为 `refund_template_txid`，因此可独立投递的凭证能直接路由到其费用池；Buyer 验证内容哈希、报价、期限和 Seller 身份后，才构造 005 无签名状态并产生 detached Buyer signature。
