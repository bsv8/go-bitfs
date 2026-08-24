---
id: 004-content-delivery-requirements
title: 004 · 内容交付凭证需求
---

# 004 · 内容交付凭证需求

## 要解决什么

卖方收到 003 后，需要原子交付整个有序 payload 批次：一个交付包承载被授权哈希批次的全部 payload，全有或全无。交付不能把报价、费用池、哈希或请求参数逐项回传；它只要明确回答“这是对哪一张买方授权的交付，以及交付的确切字节是什么”。

## 最小交付关系

004 是 wire Kind 6 五元外壳，卖方签名通过 `SignWireDocument(1, 6, ...)` 覆盖精确 `content_delivery_cbor`。签名文档只携带 `PaymentAuthorizationID`，payload 批次作为 attachment 传输。它不携带费用池 ID 和内容哈希——两者都由应用按授权 ID 定位的本地保存原始 003 恢复。本地找不到对应 003 的 004 只能暂存/死信（或请求对端重发 003）；接收方绝不能从 payload 或连接状态猜测订单和费用池。

```text
BuyerSignature -> payment_authorization_cbor（SignWireDocument(1, 5, ...)）
payment_authorization_cbor -> ordered content_hashes_cbor + 池 + 序号 + 金额
PaymentAuthorizationID = SHA-256(payment_authorization_cbor)
content_delivery_cbor = deterministic-CBOR([payment_authorization_id])
SellerSignature -> content_delivery_cbor   （SignWireDocument(1, 6, ...)）
ContentPayloadsCBOR[i] -> SHA-256 -> ContentHashesCBOR[i]
```

payload 未直接入签，因此验收必须逐项执行：数量严格等于哈希数量、顺序保持一致、每项 SHA-256 等于被提交哈希、seed/block 归属与协议期望长度校验，以及重算聚合价格并与绝对累计金额精确匹配。任一项失败即整批拒绝——不允许部分付款、不允许缺失项计零价、不允许按前缀接受。

卖方通过统一 `SignWireDocument(1, 6, ...)` 对精确 content_delivery_cbor 签名（对类型化签名输入内部再做一次 SHA-256，low-S DER）；类型化输入把版本和 Kind 与 exact 文档一起纳入认证。对裸哈希、hex 文本、payload 或预哈希摘要的签名都不是本协议。

## 交付时限的边界

`DeliveryDeadlineUnix` 来自 003。买方以验证交付时一次性读取的本地时间决定是否接受；卖方自行填写一个时间戳不能证明网络上何时送达，因此协议不把卖方声明时间当作客观证据。004 本身不带任何时间字段。

卖方的签名证明卖方对该授权承诺并提供了可验证 payload，但不能单独证明买方在截止前实际收到。买方在 005 对付款状态的签名，才是验收并付款的强证据。007 Claim 会携带卖方验证过的精确 payload bundle 作为托管事实，但仍不裁定网络送达时间，也不证明买方已收到；若将来需要裁定“卖方是否按时送达而买方拒付”，须另行引入可证明接收机制。

编码细节见[内容交付凭证规范](004-content-delivery-spec.md)。
