---
id: 005-cumulative-payment-spec
title: "005 · 累计支付规范"
---

# 005 · 累计支付规范

005 是对 003 最终付款授权的正常履行消息。它是一份**最小付款凭证**：`payment_authorization_id` 加 Buyer 交易签名。费用池关联 ID（`RefundTemplateTxID`）与未签名状态交易**不再进入报文**；买方和卖方都通过 MultisigPool v4.0.0 唯一的 `BuildPaymentUpdate` 实现，用 OpeningProof、上一 PaymentState 和按 ID 引用的签名 003 在本地确定性重建同一笔未签名状态交易。

`payment_authorization_id` 是内容寻址查找键，不是可逆编码：它绝不能当作池 ID、解码出金额或序号，也不能从连接猜测。接收方应用必须先按该 ID 找到保存的精确原始签名 003，任何验证才有意义。

## wire 外形（Kind 7）

```text
kind-7-payment-update = [
    1,                                    ; wire-version，由 encoder 固定注入
    7,                                    ; wire kind
    payment_authorization_id,             ; bstr .size 32 = SHA-256(exact payment_authorization_cbor)
    buyer_payment_transaction_signature   ; 对本地重建状态交易 sighash 的签名
]
```

旧容器——包括携带退款模板 txid、授权哈希与 raw candidate 的 v1 之前五元容器——一律直接拒绝；`protocol.WireVersion = 1` 内不存在按长度选择的旧 decoder。decoder 同样拒绝缺失字段、多余字段、错误版本、非定长编码、tag、非最短长度头、非规范编码与尾随字节，并返回稳定的无效证据错误。

## 硬切换门禁

这份四元 Kind 7 形状在上线时一次性替换了所有切换前容器：没有双 decoder，也没有迁移适配层。部署前必须确认不存在仍携带旧 005 字节的独立外部客户端、持久化队列或生产节点；一旦存在，必须停止同 major 硬切换，改定新 major/transport family 并制定明确迁移策略。两种互不兼容的形状绝不能同时自称在同一版本内可互操作。

`payment_authorization_id` 恰为 32 字节，等于 exact 签名 003 付款授权文档的 SHA-256。`buyer_payment_transaction_signature` 是对本地重建的未签名状态交易做 MultisigPool v4 sighash（SHA-256d preimage，ForkID|All）的 low-S DER ECDSA 签名——绝不是对授权 ID、payment authorization CBOR、Kind 7 CBOR、txid 或任何文本形式签名。

## 重建的状态交易

所有状态交易都恰好有三个资金输出，顺序固定为 `[Buyer, Seller, Arbiter]`：output[0] 是 Buyer，output[1] 是带绝对累计金额的 Seller，output[2] 是金额固定为 0 的 Arbiter。输入 outpoint、Buyer 金额、Arbiter 零金额、手续费、序号与 locktime 由下式唯一确定：

```text
OpeningProof
+ previous PaymentState
+ payment_authorization_cbor.PaymentSequence
+ payment_authorization_cbor.SellerAmountAfterSatoshis
+ 固定的 MultisigPool v4 构造规则
= 精确的未签名付款状态交易
```

重建的交易必须恰好有一个输入和三个资金输出，输入 `unlockingScript` 为空。Seller 对重建交易验证 Buyer 签名及协议规范状态后，对同一笔重建交易产生独立 Seller 签名，最终只通过唯一的 Buyer+Seller 合并入口（`MergeArbitratedPoolBuyerSellerSignatures`）生成完整交易。如果 Buyer 与 Seller 重建出的字节出现差异，这是必须记录并修复的硬失败——绝不能退回报文携带 raw 的旧设计。

## 应用路由与边界

应用自己维护唯一索引 `payment_authorization_id -> {exact_signed_003, content_delivery_state, refund_template_txid, processing_status}`。收到 Kind 7 后卖方应用必须：严格解码四元 005；按 ID 载入精确原始 003；逐项交叉比较绑定；在自己的事务/CAS 内串行化同一池的验收；再把全部显式证据交给无状态 SDK。SDK 不查数据库、不扫描池、不持有锁。

提交失败、超时或 txid/序号不一致时，调用方应用必须先持久化完整 raw/txid/sequence/auth-ID candidate，并按自身节点策略以 txid 或 outpoint 对账，之后才允许推进 accepted-payment 记录。协议 SDK 不定义任何不确定状态、持久化钩子、节点接口或对账流程；广播与结果记录属于应用职责。

007 仲裁路径不依赖这份最小 005。它携带 Seller 签名的 Claim（含 source amount/script、RefundTx、Buyer 签名 003 授权与 exact 004 payload bundle），刻意省略 OpeningProof、FundingTx、previous state、candidate raw 与 Seller 交易签名；Arbiter 用同一个确定性 candidate builder 独立重建，且只在应用完成托管持久化后才签名。Seller 重建 candidate 并经 `MergeArbitratedPoolSellerArbiterSignatures` 合并。
