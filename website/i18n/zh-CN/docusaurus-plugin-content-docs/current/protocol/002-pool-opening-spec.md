---
id: 002-pool-opening-spec
title: 002 · 费用池开闭规范
---

# 002 · 费用池开闭规范

Buyer 使用 MultisigPool v4 的 `ArbitratedPoolRoles{Buyer, Seller, Arbiter}` 创建池锁，公钥顺序固定为 `[Buyer, Seller, Arbiter]`。

Opening/refund state 必须恰好包含三个资金输出：Buyer、Seller、Arbiter。Seller 和 Arbiter 初始金额为 0，Arbiter 输出仍必须存在。Opening sequence 由 MultisigPool 依赖返回，当前为 2；go-bitfs 不重写 sequence、locktime、手续费或脚本。

Buyer 对无签名 RefundTx 产生 detached Buyer signature，Seller 对同一无签名交易产生 detached Seller signature。双方保存完整 OpeningProof 后才交付/广播 FundingTx。到期退款只通过 `MergeArbitratedPoolBuyerSellerSignatures` 合并。

FundingTx 的资金池输出必须固定在索引 0，RefundTx 直接携带该 outpoint。RefundTemplateTxID 是未签名 RefundTx 的规范交易 ID，也是费用池统一关联 ID；FundingTxID 取自其输入。资金池金额由 RefundTx 的 Buyer 输出加规范 MultisigPool 手续费推导，资金池锁定脚本由按角色排序的三方公钥推导。这些值不得在预签请求或 OpeningProof 中重复传输。

Kind 2 RefundPresignRequest 是固定七元 wire 数组 `[1, 2, refund_template_raw, buyer_public_key, seller_public_key, arbiter_public_key, miner_fee_rate_satoshis_per_kilobyte, buyer_refund_transaction_signature]`，运行于 `protocol.WireVersion = 1`。wire 版本已唯一确定 MultisigPool 交易规则，因此禁止重复携带判别字段。

本地持久化的 OpeningProof 只保留无法从其他字段恢复的原始证据（退款模板原文、角色公钥、费率、双方签名、资金交易）。它是应用侧结构，不是 wire Kind。使用 proof 时即时推导 RefundTemplateTxID、FundingTxID、固定输出索引、资金池金额和锁定脚本；这些派生值可以作为数据库索引，但不得重新序列化进 OpeningProof。

### Kind 12 · PoolCloseRequest（Buyer → Seller）

关池沿用上文定义的费用池关联 ID 和开池证据。Kind 12 是固定五元 deterministic-CBOR 买方请求：

```text
[1, 12,
  refund_template_txid,
  unsigned_close_transaction_raw,
  buyer_close_transaction_signature]
```

- `refund_template_txid`：从买方 OpeningProof 推导出的非零 32 字节费用池关联 ID，必须是首个业务字段。
- `unsigned_close_transaction_raw`：买方基于自行选定的付款状态构造出的最终关闭候选交易原文。
- `buyer_close_transaction_signature`：买方对该候选交易的分离式 MultisigPool 交易签名，不是 `SignWireDocument` 报文签名。

Seller 必须用自己的 OpeningProof 核对关联 ID，按该开池证据验证候选交易，并在签署前验证买方交易签名。

### Kind 13 · PoolCloseResponse（Seller → Buyer）

Kind 13 是固定四元 deterministic-CBOR 卖方响应：

```text
[1, 13,
  refund_template_txid,
  complete_close_transaction_raw]
```

- `refund_template_txid`：响应重复携带的费用池关联 ID，仍是首个业务字段。
- `complete_close_transaction_raw`：完整关闭交易原文，unlocking script 中包含买卖双方的交易签名。

Buyer 必须用自己的 OpeningProof 核对关联 ID，并完整验证交易后才能提交广播。

两个关池 Kind 都使用严格 deterministic-CBOR 解析，拒绝缺失、多余、畸形或非规范字段。每笔关闭交易最多 65,536 字节，且必须恰好包含一个输入、三个输出。Go 与 TypeScript SDK 对所有交易（包括资金交易）另有最多 10,000 个输入和 10,000 个输出的实现资源上限；这不是比特币共识规则。Artifact 只定义报文外形和费用池路由；存储、重试、交易广播和确认跟踪仍由应用负责。费用池关联 ID 不是关闭交易的链上交易 ID。
