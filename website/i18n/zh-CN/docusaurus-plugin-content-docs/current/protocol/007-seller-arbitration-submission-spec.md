---
id: 007-seller-arbitration-submission-spec
title: 007 · v3 卖方仲裁提交规范
---

# 007 · v3 卖方仲裁提交规范

007 定义 Seller 依据买方最终付款授权请求 Arbiter detached signature 的约束。当前协议 major 为 3，费用池绑定 `bitfs.pool.v4`，`ArbiterAmount = 0`。

## 证据包

```text
ArbitrationRequest = [
  3,
  pool_opening_proof_cbor,
  payment_authorization_cbor,
  unsigned_state_tx_raw,
  seller_transaction_signature
]

ArbitrationResponse = [
  3,
  payment_authorization_hash,
  unsigned_state_tx_hash,
  arbiter_transaction_signature
]
```

候选交易必须是 `[Buyer, Seller, Arbiter]` 三输出状态，输入解锁脚本为空，Arbiter 输出存在且金额为 0。Seller 签名和 Arbiter 签名都必须针对同一无签名交易；仲裁者不构造替代交易、不修改候选交易，也不读取外部数据库补证据。

Seller 收到响应后复核两个哈希和 Arbiter 签名，只通过 `MergeArbitratedPoolSellerArbiterSignatures` 生成最终交易。007 不要求买方为本次争议签署 005，且不允许 Buyer+Arbiter 作为 go-bitfs 业务路径。
