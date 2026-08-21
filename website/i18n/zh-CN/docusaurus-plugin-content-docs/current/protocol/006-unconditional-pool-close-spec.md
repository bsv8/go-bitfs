---
id: 006-unconditional-pool-close-spec
title: 006 · v4 协商立即关闭规范
---

# 006 · v4 协商立即关闭规范

立即关闭由 MultisigPool v4 构造最终 sequence/locktime 的三输出无签名状态，Arbiter 输出存在且金额为 0。Buyer 返回无签名交易和 detached Buyer signature；Seller 验证后产生 detached Seller signature，并通过 `MergeArbitratedPoolBuyerSellerSignatures` 返回完整最终交易。节点确认前不推进本地 accepted state。
