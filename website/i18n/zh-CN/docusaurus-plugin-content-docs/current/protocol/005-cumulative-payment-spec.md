---
id: 005-cumulative-payment-spec
title: 005 · v4 累计支付规范
---

# 005 · v4 累计支付规范

005 是对 003 最终付款授权的正常履行消息。它是一份**最小付款凭证**：授权哈希加 Buyer 交易签名。费用池关联 ID（`RefundTemplateTxID`）与未签名状态交易**不再进入报文**；买方和卖方都通过 MultisigPool v4.0.0 唯一的 `BuildPaymentUpdate` 实现，用 OpeningProof、上一 PaymentState 和授权哈希引用的签名 003 在本地确定性重建同一笔未签名状态交易。

授权哈希是内容寻址查找键，不是可逆编码：不得把它当作池 ID、解码出金额或序号，也不得从连接上下文猜测。接收方应用必须先用它查回按哈希保存的精确原始 SignedContentRequest，任何验证才能开始。

## 005 CBOR

```text
CumulativePaymentUpdateCBOR = deterministic CBOR([
  4,
  payment_authorization_hash,
  buyer_transaction_signature
])
```

切换前的 v4 五元容器（`[4, refund_template_txid, payment_authorization_hash, unsigned_state_tx_raw, buyer_transaction_signature]`）一律直接拒绝，不存在按长度选择的旧 decoder。decoder 同样拒绝缺失字段、多余字段、错误 major、非定长编码、tag、非最短长度头、非规范编码与尾随字节，并返回稳定的无效证据错误。

## 硬切换门禁

这份三元形状在上线时一次性替换了切换前的五元 v4 容器：没有双 decoder，也没有运行时迁移适配层。部署前必须确认不存在仍携带旧五元 005 字节的独立外部 v4 客户端、持久化队列或生产节点；一旦存在，必须停止同 major 硬切换，改定新 major/transport family 并制定明确迁移策略。两种互不兼容的形状绝不能同时自称可互操作的 v4。

`payment_authorization_hash` 恰为 32 字节，等于签名 003 `TermsCBOR` 的 SHA-256。`buyer_transaction_signature` 是对本地重建的未签名状态交易做 MultisigPool v4 sighash（SHA-256d preimage，ForkID|All）的 low-S DER ECDSA 签名——绝不是对授权哈希、TermsCBOR、005 CBOR、txid 或任何文本形式签名。

## 重建的状态交易

所有状态交易固定为 `[Buyer, Seller, Arbiter]` 三个资金输出：output[0] 为 Buyer，output[1] 为 Seller 的绝对累计金额，output[2] 为 Arbiter 且金额固定为 0。输入 outpoint、Buyer 金额、Arbiter 零金额、手续费、sequence 和 locktime 由下式唯一决定：

```text
OpeningProof
+ previous PaymentState
+ 003.PaymentSequence
+ 003.SellerAmountAfterSat
+ 固定的 MultisigPool v4 构造规则
= 精确的未签名付款状态交易
```

重建的交易必须恰好有一个输入和三个资金输出，输入 `unlockingScript` 为空。Seller 对重建交易验证 Buyer 签名及 v4 规范状态后，对同一笔重建交易产生独立 Seller 签名，最终只通过唯一的 Buyer+Seller 合并入口（`MergeArbitratedPoolBuyerSellerSignatures`）生成完整交易。如果 Buyer 与 Seller 重建出的字节出现差异，这是必须记录并修复的硬失败——绝不能退回报文携带 raw 的旧设计。

## 应用路由与边界

应用负责维护唯一索引 `payment_authorization_hash -> {exact_signed_003, content_delivery_state, refund_template_txid, processing_status}`。收到 Kind 7 后，卖方应用必须：严格解码三元 005；按哈希加载精确原始 003；交叉比较全部绑定；在自己的事务/CAS 中按池串行化验收；把全部显式证据交给无状态 SDK。SDK 不查询数据库、不扫描池、不持锁。

提交失败、超时或 txid/序号不一致时，调用方应用必须先持久化完整候选（raw/txid/sequence/auth hash），并在自己的节点策略确认前按 txid 或 outpoint 对账，然后才能推进 accepted-payment 记录。协议 SDK 不定义 uncertain 状态、持久化 hook、节点接口或对账流程；广播与记录结果都是调用方应用的职责。

007 仲裁不依赖这份最小 005，继续携带自足的证据包（完整 OpeningProof、原始 003、候选交易原文、Seller 签名），因为 Arbiter 不共享 Seller 的本地查找上下文。仲裁路径使用同一三输出规则，由 Seller 与 Arbiter 通过 `MergeArbitratedPoolSellerArbiterSignatures` 合并。
