---
id: 006-pool-close-requirements
title: 006 · 费用池关闭需求
---

# 006 · 费用池关闭需求

## 要解决什么

买方没有承诺必须购买多少内容，甚至可以一项也不买。因此买方不必请求卖方关闭，也不因卖方不作为而起诉；买方只需等待费用池到期并提交自己在 002 已取得的退款交易。关闭不是对报价、文件或交付重新争论。

## 利益关系

卖方若不提交任何累计付款交易，买方到期后取得全额退款。卖方每次使用并提交买方签出的累计付款状态，该交易本身在到期后将卖方累计金额和买方找零同时结算。卖方想主张买方已经签出、但自己无法正常提交的付款状态时，才由卖方发起仲裁提交。仲裁通常有成本，因此它是卖方的兜底手段，而不是买方催促关闭的工具。

## BitFS 的范围

BitFS 的仲裁提交只执行卖方提供、且可验证的最终付款授权与独立重建状态：

- 不重新裁定某个文件是否已经送达；
- 不补偿、罚款或重算买卖双方金额；
- 绝不静默扣除仲裁服务费：费用是 Receipt 明确绑定、Seller 验证后才补签的正数 `output[2]` 分配；
- 不支持买方向仲裁者提出关闭或金额请求。

买方到期退款的矿工费由退款交易既有规则承担。自 007 付费仲裁硬切换起，仲裁者的商业服务费从池内可花费余额中作为明确的正 `ArbiterAmountSatoshis` 分配到 `output[2]`：由 Buyer 余额吸收（`Buyer + Seller + Arbiter + 退款矿工费 = 池输出`），Seller 金额仍严格等于 Buyer 签署的绝对 `SellerAmountAfterSatoshis`；由卖方向仲裁者另行转账付费，或为提交交易追加输入，均不属于本协议。

## 对仲裁者的证据要求

仲裁者不是原始参与方，不能只收到一个交易 ID 或 session 标识就相信状态。所有仲裁证据必须绑定费用池的 `RefundTemplateTxID` 关联 ID，该 ID 从 Claim 的 canonical `refund_template_raw` 推导。卖方发起仲裁提交时，必须提供精确 source amount/script、RefundTx、Buyer 签名的 003 条款、Seller Claim 签名和已验证的 004 payload bundle；不得要求买方为本次争议签署 005，也不得在线上携带 OpeningProof、FundingTx、费率、previous state、candidate raw 或 Seller transaction signature。仲裁者独立验证 payload 托管事实，用同一确定性费用池构造器按其明确决定的正费用重建付费 candidate：先签署仲裁交易签名，再把 Claim ID、该费用和交易签名放入回执并通过 `SignWireDocument(1, 9, exact_receipt_cbor)` 签名。完整要求见 007。

具体关闭报文和 BitFS 的未定边界见[费用池无条件关闭规范](006-unconditional-pool-close-spec.md)。
