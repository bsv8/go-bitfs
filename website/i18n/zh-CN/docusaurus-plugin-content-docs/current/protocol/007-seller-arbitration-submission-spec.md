---
id: 007-seller-arbitration-submission-spec
title: 007 · v4 卖方仲裁提交规范
---

# 007 · v4 卖方仲裁提交规范

007 定义 Seller 依据买方最终付款授权请求 Arbiter detached signature 的约束。当前协议 major 为 4，`ArbiterAmount = 0`。

## 证据包

```text
ArbitrationRequest = [
  4,
  pool_opening_proof_cbor,
  payment_authorization_cbor,
  unsigned_state_tx_raw,
  seller_transaction_signature
]

ArbitrationResponse = [
  4,
  payment_authorization_hash,
  unsigned_state_tx_hash,
  arbiter_transaction_signature
]
```

`pool_opening_proof_cbor` 是 002 定义的九字段 v4 OpeningProof。它携带 RefundTx/FundingTx 原文、参与方公钥、费率和双方退款签名；不携带可推导的交易 ID、固定输出索引、资金池金额、锁定脚本或重复的 MultisigPool 判别字段。

候选交易必须是 `[Buyer, Seller, Arbiter]` 三输出状态，输入解锁脚本为空，Arbiter 输出存在且金额为 0。Seller 签名和 Arbiter 签名都必须针对同一无签名交易；仲裁者不构造替代交易、不修改候选交易，也不读取外部数据库补证据。

Seller 收到响应后复核两个哈希和 Arbiter 签名，只通过 `MergeArbitratedPoolSellerArbiterSignatures` 生成最终交易。007 不要求买方为本次争议签署 005，且不允许 Buyer+Arbiter 作为 go-bitfs 业务路径。
