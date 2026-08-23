---
id: 007-seller-arbitration-submission-requirements
title: 007 · 卖方仲裁提交要求
---

# 007 · 卖方仲裁提交要求

007 是 Buyer 签名的 003 无法正常完成 004/005 时使用的 v4 托管与结算异常分支。Seller 签署 Claim，Arbiter 验证并托管精确内容，独立构造付款交易；应用确认持久化后，Arbiter 才能签交易。

## 必须提交的证据

Seller 必须发送新的五元 Kind 8。Claim 只包含：

- 声明的 pool output satoshis 和固定角色顺序的规范 P2MS locking script；
- canonical unsigned RefundTx 原文；
- 精确的 Buyer-signed 003 `TermsCBOR` 和 Buyer signature。

外层 Request 另含对 `[4, 8, exact_claim_cbor]` 的 Seller 消息签名，以及 canonical 的 1–64 项 `content_payloads_cbor`。不得携带 OpeningProof、FundingTx、费率、previous state、candidate raw、重复的 `RefundTemplateTxID` 或 Seller transaction signature。

SDK 验证角色脚本、Buyer 条款签名、RefundTx ID 与条款绑定、RefundTx 形状、金额算术、payload 数量/顺序/大小/hash 和所有 canonical CBOR。它不声称验证链上 UTXO 存在、确认或未花费；错误 source context 应由应用记录为卖方 source 不可花费的对账失败。

## 仲裁方边界

应用必须先持久化精确入站请求和 payload bundle：

```text
收到 raw Kind 8
  -> PreparePayment
  -> 原子托管持久化
  -> SignPreparedPayment
  -> 持久化/发送精确 Kind 9
```

`PreparePayment` 不产生交易签名副作用，返回带深复制 getter 的 opaque prepared evidence。应用重启后必须从已保存的精确 Kind 8 重新 Prepare，不得伪造 opaque 值。

Result 同时提交 Seller Claim signing-domain hash、精确 payload 子文档 hash 和精确 unsigned candidate hash。Result 消息签名与 `ForkID|All` 交易签名是两份独立凭证，不能互相替代。

## Seller 完成

Seller 收到 Kind 9 后必须从 Claim primitives 独立重建 candidate，验 Buyer signature、三个 Result hash、Result 消息签名和 Arbiter transaction signature，再生成自身交易签名。合并只能通过 `MergeArbitratedPoolSellerArbiterSignatures`。广播、对账、Buyer 取件鉴权、retention 和幂等索引均由应用负责。
