---
id: 002-pool-opening-spec
title: 002 · v4 费用池开池规范
---

# 002 · v4 费用池开池规范

Buyer 使用 MultisigPool v4 的 `ArbitratedPoolRoles{Buyer, Seller, Arbiter}` 创建池锁，公钥顺序固定为 `[Buyer, Seller, Arbiter]`。

Opening/refund state 必须恰好包含三个资金输出：Buyer、Seller、Arbiter。Seller 和 Arbiter 初始金额为 0，Arbiter 输出仍必须存在。Opening sequence 由 v4 返回，当前为 2；go-bitfs 不重写 sequence、locktime、手续费或脚本。

Buyer 对无签名 RefundTx 产生 detached Buyer signature，Seller 对同一无签名交易产生 detached Seller signature。双方保存完整 OpeningProof 后才交付/广播 FundingTx。到期退款只通过 `MergeArbitratedPoolBuyerSellerSignatures` 合并。

FundingTx 的资金池输出必须固定在索引 0，RefundTx 直接携带该 outpoint。SpendTxID 是 RefundTx 的规范交易 ID，FundingTxID 取自其输入。资金池金额由 RefundTx 的 Buyer 输出加规范 MultisigPool 手续费推导，资金池锁定脚本由按角色排序的三方公钥推导。这些值不得在预签请求或 OpeningProof 中重复传输。

RefundPresignRequest deterministic CBOR 为 `[4, refund_tx, buyer_pubkey, seller_pubkey, arbiter_pubkey, fee_rate, buyer_signature]`。工作流版本 4 已唯一确定 MultisigPool 协议及其版本，因此禁止重复携带判别字段。

传输和本地持久化的 OpeningProof deterministic CBOR 为 `[4, refund_tx, buyer_pubkey, seller_pubkey, arbiter_pubkey, fee_rate, buyer_signature, seller_signature, funding_tx]`，只保留无法从其他字段恢复的原始证据。使用 proof 时即时推导 SpendTxID、FundingTxID、固定输出索引、资金池金额和锁定脚本；这些派生值可以作为数据库索引，但不得重新序列化进 OpeningProof。
