---
id: 007-seller-arbitration-submission-spec
title: 007 · v4 卖方仲裁提交规范
---

# 007 · v4 卖方仲裁提交规范

007 是破坏式 v4 硬切换。旧五元 Kind 9 Result 响应无效。Kind 9 现为四元回执响应，向仲裁方支付一笔应用明确决定的正费用，回执把 Claim ID、该费用和仲裁交易签名用一条普通消息签名绑定在一起。仲裁方接收卖方签名的 source context、买方签名条款和精确 payload bundle，独立重建付费的付款交易，并且只有应用持久化托管证据后才签名。

## Wire 文档

```text
ArbitrationRequest = [4, 8, arbitration_claim_cbor, seller_claim_signature, content_payloads_cbor]
ArbitrationClaim = [pool_output_satoshis, pool_output_locking_script, refund_template_raw, terms_cbor, buyer_signature]
ArbitrationResponse = [4, 9, arbitration_receipt_cbor, arbiter_receipt_signature]
ArbitrationReceipt = [arbitration_claim_id, arbiter_amount_sat, arbiter_transaction_signature]
```

`Claim` 和 `Receipt` 内层不含 version/type。transport Kind 必须与本体第二项一致。所有子文档均为嵌入 `bstr` 的 deterministic CBOR；非规范字节、错误数组长度、tag、indefinite length 和尾随字节必须拒绝。旧五元 Kind 9 字节确定性失败；不存在双形状 decoder。

卖方消息签名域严格为：

```text
seller_claim_signing_cbor = [4, 8, exact_claim_cbor]
seller_claim_signature = SignMessage(SellerKey, seller_claim_signing_cbor)
```

回执消息签名域严格为：

```text
arbiter_receipt_signing_cbor = [4, 9, exact_receipt_cbor]
arbiter_receipt_signature = SignMessage(ArbiterKey, arbiter_receipt_signing_cbor)
```

Claim ID 即 `arbitration_claim_id = SHA-256(seller_claim_signing_cbor)`，固定 32 字节。它间接绑定精确 Claim CBOR、精确 Buyer 条款和有序 content hashes。成功回执要求 `arbiter_amount_sat > 0`；零不代表免费、拒绝或未决定。交易签名是独立的 `ForkID|All` 签名，不能代替回执消息签名；两种签名不能互相填入对方的验证路径。

## Claim、托管与交易构造

pool locking script 必须是固定 `[Buyer, Seller, Arbiter]` 顺序的规范压缩公钥脚本：

```text
OP_2 PUSHDATA(33-byte Buyer) PUSHDATA(33-byte Seller)
PUSHDATA(33-byte Arbiter) OP_3 OP_CHECKMULTISIG
```

仲裁方验证 Buyer 对精确 `terms_cbor` 的签名，从 `refund_template_raw` 推导 `RefundTemplateTxID` 并与 Buyer 条款比较。请求不携带 OpeningProof、FundingTx、费率、previous state、candidate raw 或 Seller transaction signature。

payload 必须是 1–64 项非空 canonical bundle，数量、顺序、大小和每项 SHA-256 必须与 003 完全一致；任一项失败整批拒绝。payload 不复制进卖方 Claim 签名，而是通过 Buyer 签入的 content hashes 与 Claim ID 间接绑定。

source context 只是卖方签名承担的离线声明。SDK 不证明金额/脚本属于链上 FundingTx output，不查询确认数，也不证明 UTXO 未花费。错误 source context 会使最终 ForkID 签名不可用，风险由卖方承担。

唯一 builder 只接受 pool amount、locking script、RefundTx raw、目标 sequence、绝对 Seller amount 和明确的正仲裁费。它从 RefundTx 输出推导保留 fee（退款模板本身仍要求 Seller/Arbiter 初始金额为零），构造恰好三个有资金输出：

```text
Buyer   = spendable - SellerAmountAfterSat - ArbiterAmountSat
Seller  = SellerAmountAfterSat
Arbiter = ArbiterAmountSat (> 0)
其中 spendable = pool - refund_fee
```

`Buyer + Seller + Arbiter + 退款矿工费` 恒等于池输出金额，全部使用先比较后减法的无溢出算术。Seller 金额已超过 spendable 或费用超过剩余余额时返回 `pool.ErrInsufficientBalance`；零费用按 invalid evidence 拒绝。恰好耗尽 Buyer 余额（Buyer 输出为零）在三个输出仍存在时是合法边界。source output 仅注入内存 sighash context，不序列化进 RawTx。卖方和仲裁方必须调用同一核心并得到逐字节相同的 candidate。

应用流程固定为：

```text
应用按自己的收费策略计算 arbiter_amount_sat
PreparePayment(request, blockHeight, arbiterAmountSat)
  -> 应用原子持久化精确 Kind 8、Claim ID、费用与 payload bundle
  -> SignPreparedPayment
  -> 持久化/发送精确 Kind 9
```

SDK 不提供数据库、对象存储、HTTP、广播、UTXO 查询或费率策略。应用必须保存 exact request/response 字节用于幂等以及托管留存；买方取件的 wire 与签名域已由 SDK 通过 008（Kind 10/11）固定，持久化、nonce 去重、TLS 与 retention 仍由应用负责。重放以 exact 字节为门槛，不能只看 Claim ID：只有 Claim ID 与 exact Kind 8 字节完全相同才原样重放保存的响应字节，不重新计价、不重签；同 ID 不同 exact Claim 属于 hash collision 报警；同 Claim 但外层签名或 payload 不同时，先用已冻结费用完整验证（无效变体按证据错误拒绝，完全有效的变体记为重复证据冲突）；不同 Claim ID 建立独立记录。

卖方收到 Kind 9 后：从自己的 Claim 字节重算 Claim ID 并比较；从角色脚本恢复仲裁方公钥，验证 `[4, 9, exact_receipt_cbor]` 上的回执普通消息签名；用回执金额本地重建 candidate 并验证仲裁交易签名；全部通过后才生成自身交易签名并调用 `MergeArbitratedPoolSellerArbiterSignatures`。完成状态的 `ArbiterAmountSat` 必须等于回执金额，Seller 金额等于 Buyer 授权的绝对金额。
