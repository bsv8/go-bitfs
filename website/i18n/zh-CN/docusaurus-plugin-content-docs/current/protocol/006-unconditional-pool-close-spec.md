---
id: 006-unconditional-pool-close-spec
title: 006 · 协商立即关闭规范
---

# 006 · 协商立即关闭规范

费用池生命周期的 wire 定义与建立 `RefundTemplateTxID` 的开池报文统一归属[002 · 费用池开闭规范](002-pool-opening-spec.md)。002 定义 Kind 12 和 Kind 13 的精确数组结构；本文说明关闭交易行为和验证边界。

立即关闭由 MultisigPool v4 构造最终 sequence/locktime 的三输出无签名状态，Arbiter 输出存在且金额为 0。Buyer 对该精确无签名交易签名。Seller 验证请求后补上自己的签名，并返回完整最终交易。节点确认前不推进本地 accepted state。

### Wire 交换

买方发送 002 定义的 exact Kind 12 请求，其中先携带费用池 ID，再携带未签名最终关闭交易和买方分离式交易签名。卖方用自己的开池证据核对 ID、验证候选并签名，然后返回 exact Kind 13 响应。买方核对重复的费用池 ID，并完整验证交易。

两个 Artifact 定义 BitFS 报文格式；传输、持久化、重试策略、节点提交和确认跟踪仍由应用负责。节点提交接口使用完整交易原文和其真实链上 txid；`RefundTemplateTxID` 只是费用池关联 ID，不能冒充该 txid。
