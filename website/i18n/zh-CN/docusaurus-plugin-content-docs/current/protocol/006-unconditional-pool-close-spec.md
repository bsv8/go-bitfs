---
id: 006-unconditional-pool-close-spec
title: 006 · v4 协商立即关闭规范
---

# 006 · v4 协商立即关闭规范

立即关闭由 MultisigPool v4 构造最终 sequence/locktime 的三输出无签名状态，Arbiter 输出存在且金额为 0。Buyer 返回无签名交易和 detached Buyer signature；Seller 验证后产生 detached Seller signature，并通过 `MergeArbitratedPoolBuyerSellerSignatures` 返回完整最终交易。节点确认前不推进本地 accepted state。

当前没有独立 wire 006 容器：双方在公开输入以及调用方自行保存的应用本地记录中（SDK 不持有任何状态），只使用费用池的 `RefundTemplateTxID` 关联 ID 寻址。节点提交接口仍以 raw transaction 和真实链上 txid 为真值；关联 ID 决不冒充链上 txid，最终链上退款 txid 与 `RefundTemplateTxID` 保持明确区分。如果以后增加可独立投递的 006 报文，其首个业务字段必须是 `refund_template_txid`。
