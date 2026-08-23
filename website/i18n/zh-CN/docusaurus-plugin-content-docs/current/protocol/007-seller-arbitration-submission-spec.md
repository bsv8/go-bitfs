---
id: 007-seller-arbitration-submission-spec
title: 007 · v4 卖方仲裁提交规范
---

# 007 · v4 卖方仲裁提交规范

007 是破坏式 v4 硬切换。旧六元请求和旧五元响应均无效。仲裁方接收卖方签名的 source context、买方签名条款和精确 payload bundle，独立重建付款交易，并且只有应用持久化托管证据后才签名。

## Wire 文档

```text
ArbitrationRequest = [4, 8, arbitration_claim_cbor, seller_claim_signature, content_payloads_cbor]
ArbitrationClaim = [pool_output_satoshis, pool_output_locking_script, refund_template_raw, terms_cbor, buyer_signature]
ArbitrationResponse = [4, 9, arbitration_result_cbor, arbiter_result_signature, arbiter_transaction_signature]
ArbitrationResult = [request_commitment, content_payloads_hash, unsigned_state_tx_hash]
```

`Claim` 和 `Result` 内层不含 version/type。transport Kind 必须与本体第二项一致。所有子文档均为嵌入 `bstr` 的 deterministic CBOR；非规范字节、错误数组长度、tag、indefinite length 和尾随字节必须拒绝。

卖方消息签名域严格为：

```text
seller_claim_signing_cbor = [4, 8, exact_claim_cbor]
seller_claim_signature = SignMessage(SellerKey, seller_claim_signing_cbor)
```

Result 消息签名域严格为：

```text
arbiter_result_signing_cbor = [4, 9, exact_result_cbor]
arbiter_result_signature = SignMessage(ArbiterKey, arbiter_result_signing_cbor)
```

`request_commitment = SHA-256(seller_claim_signing_cbor)`；`content_payloads_hash = SHA-256(exact content_payloads_cbor)`；`unsigned_state_tx_hash = SHA-256(exact unsigned candidate transaction)`。交易签名是独立的 `ForkID|All` 签名，不能代替 Result 消息签名。

## Claim、托管与交易构造

pool locking script 必须是固定 `[Buyer, Seller, Arbiter]` 顺序的规范压缩公钥脚本：

```text
OP_2 PUSHDATA(33-byte Buyer) PUSHDATA(33-byte Seller)
PUSHDATA(33-byte Arbiter) OP_3 OP_CHECKMULTISIG
```

仲裁方验证 Buyer 对精确 `terms_cbor` 的签名，从 `refund_template_raw` 推导 `RefundTemplateTxID` 并与 Buyer 条款比较。请求不携带 OpeningProof、FundingTx、费率、previous state、candidate raw 或 Seller transaction signature。

payload 必须是 1–64 项非空 canonical bundle，数量、顺序、大小和每项 SHA-256 必须与 003 完全一致；任一项失败整批拒绝。payload 不复制进卖方 Claim 签名，而是通过 Buyer 签入的 content hashes 间接绑定并由 Result 提交 custody hash。

source context 只是卖方签名承担的离线声明。SDK 不证明金额/脚本属于链上 FundingTx output，不查询确认数，也不证明 UTXO 未花费。错误 source context 会使最终 ForkID 签名不可用，风险由卖方承担。

唯一 builder 只接受 pool amount、locking script、RefundTx raw、目标 sequence 和绝对 Seller amount。它从 RefundTx 输出推导保留 fee，构造 Buyer/Seller/Arbiter 三输出 candidate；source output 仅注入内存 sighash context，不序列化进 RawTx。卖方和仲裁方必须调用同一核心并得到逐字节相同的 candidate。

应用流程固定为：

```text
PreparePayment
  -> 应用原子持久化精确 Kind 8 与 payload bundle
  -> SignPreparedPayment
  -> 持久化/发送精确 Kind 9
```

SDK 不提供数据库、对象存储、HTTP、广播或 UTXO 查询。卖方收到 Kind 9 后重建 candidate，验三个 Result hash、Result 消息签名和仲裁交易签名，最后才生成自身交易签名并调用 `MergeArbitratedPoolSellerArbiterSignatures`。
