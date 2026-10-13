---
id: 007-seller-arbitration-submission-requirements
title: 007 · 卖方仲裁提交要求
---

# 007 · 卖方仲裁提交要求

007 是 Buyer 签名的 003 无法正常完成 004/005 时使用的托管与结算异常分支。Seller 签署 Claim，Arbiter 验证并托管精确内容，决定一笔正的仲裁费，独立构造付费的付款交易；应用确认持久化后，Arbiter 才能签名。

## 必须提交的证据

Seller 必须发送五元 Kind 8。Claim 只包含：

- 声明的 pool output satoshis 和固定角色顺序的规范 P2MS locking script；
- canonical unsigned RefundTx 原文；
- 精确的 Buyer 签名 003 payment authorization 文档与 Buyer 签名。

外层 Request 另含 `SignWireDocument(1, 8, exact_claim_cbor)` 的 Seller 消息签名，以及 canonical 的 1–64 项 `content_payloads_cbor`。不得携带 OpeningProof、FundingTx、费率、previous state、candidate raw、重复的 `RefundTemplateTxID` 或 Seller transaction signature。不得携带仲裁费用：费用只有在 Arbiter 收到并验证 payload 之后才确定。

SDK 验证角色脚本、Buyer 条款签名、RefundTx ID 与条款绑定、RefundTx 形状、金额算术、payload 数量/顺序/大小/hash 和所有 canonical CBOR。它不声称验证链上 UTXO 存在、确认或未花费；错误 source context 应由应用记录为卖方 source 不可花费的对账失败。

## 仲裁方边界

应用必须在计价和签名之前完成链上 UTXO 前置检查。SDK 绝不查询节点；生产服务必须验证 Claim 的 outpoint 存在、金额与 Claim 一致、script 与池锁定脚本一致，且已确认、未花费。UTXO 查询失败、超时或状态不确定时必须拒绝签名——“不确定”绝不能当作可花费，也不得产生降级或免费响应。

应用必须用自己的收费策略对精确 `len(ContentPayloadsCBOR)` 计算（只允许整数公式）正的 `arbiter_amount_sat`，然后在请求任何签名之前原子持久化精确入站请求、payload bundle、派生的 Claim ID 与冻结费用：

```text
收到 raw Kind 8 -> 严格解码 -> 证据验证
  -> 应用验证链上 UTXO
  -> 应用计价
  -> arbiter.PrepareArbitration(facts, rawKind8, arbiterAmountSatoshis)
  -> 原子托管持久化（只追加：request、payload、Claim ID 与费用一旦写入
     即不可变）
  -> arbiter.SignPreparedArbitration(ctx, facts, prepared, signer)
  -> 持久化/发送精确 Kind 9
```

零费用在任何持久化或签名之前按 invalid evidence 失败；扣除 Buyer 授权 Seller 金额后放不下的费用返回 `CodeInsufficientBalance` 错误分类，不存在免费或部分收费回退。

`arbiter.PrepareArbitration` 不产生交易签名副作用，返回带深复制 getter 的 opaque prepared evidence（Claim ID、冻结费用、授权哈希、payload、deadline、unsigned candidate）。应用重启后必须从已保存的精确原始 Kind 8 字节与保存的费用重新 Prepare，不得伪造 opaque 值。托管记录只追加：签名完成后，exact canonical Kind 9 字节附加到同一记录上，不覆盖 request、payload、Claim ID 或费用。

回执通过 `SignWireDocument(1, 9, exact_receipt_cbor)` 普通消息签名把 Claim ID、绝对仲裁金额和精确 `ForkID|All` 交易签名绑定在一起。回执消息签名与交易签名是两份独立凭证，不能互相替代。

重放以 Claim ID 为索引，但以 exact 字节为门槛。严格解码入站 Kind 8 并派生 Claim ID 之后：

1. Claim ID 与 exact Kind 8 字节完全相同才原样重放已保存响应，不重新计价、不重新签名；
2. 同 Claim ID 但 exact Claim 字节不同属于 hash collision：停止自动流程并报警，绝不覆盖原记录；
3. exact Claim 相同但外层 Seller signature 或 payload bundle 不同时，必须使用已冻结费用完整执行 arbiter.PrepareArbitration——验证失败按 invalid evidence 拒绝，不得触发 hash collision 报警；完全有效但字节仍不同的变体记为重复证据冲突，停止自动流程；
4. Claim ID 不同则建立独立托管记录。

## Seller 完成

Seller 收到 Kind 9 后必须从 Claim primitives 加回执金额独立重建付费 candidate：从自身 Claim 字节重算 Claim ID 并比较，验 Buyer signature、回执消息签名（仲裁方公钥从角色脚本恢复）和 Arbiter transaction signature，再生成自身交易签名。合并只能通过 `MergeArbitratedPoolSellerArbiterSignatures`。广播、对账、retention 和幂等索引均由应用负责；Buyer 取件的 wire 与签名域已由 SDK 通过 008（Kind 10/11）固定，应用仍负责持久化、nonce 原子去重、TLS 传输与 retention。Claim ID、费用、交易签名或回执签名任一篡改都拒绝整个响应。
