---
id: 005-cumulative-payment-spec
title: 005 · v4 累计支付规范
---

# 005 · v4 累计支付规范

005 是对 003 最终付款授权的正常履行消息。交易模板、费用、序号、输出和签名由 MultisigPool v4.0.0 唯一决定；go-bitfs 只传递授权哈希、无签名状态交易和独立 Buyer 签名。

所有状态交易固定为 `[Buyer, Seller, Arbiter]` 三个资金输出：output[0] 为 Buyer，output[1] 为 Seller 的绝对累计金额，output[2] 为 Arbiter 且金额固定为 0。Buyer 金额和手续费由 MultisigPool v4 计算，不能由业务层复制或修补。

## 005 CBOR

```text
CumulativePaymentUpdateCBOR = deterministic CBOR([
  4,
  refund_template_txid,
  payment_authorization_hash,
  unsigned_state_tx_raw,
  buyer_transaction_signature
])
```

无签名交易必须恰好有一个输入和三个资金输出，输入 `unlockingScript` 为空，不能携带单个签名或最终双签交易。Seller 验证 Buyer 独立签名及 v4 规范状态后，对同一无签名交易产生独立 Seller 签名，最终只通过 `MergeArbitratedPoolBuyerSellerSignatures` 生成完整交易。

提交失败、超时或 txid/序号不一致时，调用方应用在自己的节点策略确认提交的交易之前，不得推进自己的 accepted-payment 记录；结果不明确时，应用可以在应用本地记录一个 uncertain 状态，并按 txid 或 outpoint 自行对账。协议 SDK 不定义 uncertain 状态、持久化 hook、节点接口或对账流程；广播与记录结果都是调用方应用的职责。

007 仲裁不依赖本次 005 的 Buyer 签名。仲裁路径使用同一三输出规则，由 Seller 与 Arbiter 通过 `MergeArbitratedPoolSellerArbiterSignatures` 合并。
