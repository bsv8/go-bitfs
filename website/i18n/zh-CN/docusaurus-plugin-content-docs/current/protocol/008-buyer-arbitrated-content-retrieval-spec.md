---
id: 008-buyer-arbitrated-content-retrieval-spec
title: 008 · v4 买方仲裁托管内容取回规范
---

# 008 · v4 买方仲裁托管内容取回规范

008 为现有 007 Seller 仲裁托管补齐 Buyer 取件路径。Seller 与 Buyer 无法直连、但二者均能连接 Arbiter 时，Seller 继续通过 Kind 8 把精确 payload bundle 托管给 Arbiter，Arbiter 按现有 Kind 9 完成付费仲裁回执；Buyer 使用自己可独立计算的 `ArbitrationClaimID` 定位托管记录，经自己公钥签名鉴权后，从 Arbiter 取回 exact Kind 8/9 证据和其中的精确 payload bundle。

这是 v4 一次性硬切换：Kind 10/11 只存在以下唯一形状。没有兼容 decoder、feature flag、双形状或按字段是否为空的猜测。

## Wire 文档

### Kind 10 · ArbitrationContentRequest（买方 → 仲裁方）

wire 真值：`[4, 10, arbitration_claim_id, retrieval_nonce, buyer_retrieval_signature]`

```text
ArbitrationContentRequest = [
  4,
  10,
  arbitration_claim_id,
  retrieval_nonce,
  buyer_retrieval_signature
]
```

约束：

```text
arbitration_claim_id      = bstr .size 32
retrieval_nonce           = bstr .size 32   ; 禁止全零
buyer_retrieval_signature = bstr .size (1..256)
```

请求不携带任何其他字段：不重复 BuyerPubKey、RefundTemplateTxID、PaymentAuthorizationHash、OpeningProof、TermsCBOR 或 ClaimCBOR——仲裁方从 Claim ID 对应的已存 Claim 恢复全部角色公钥。最大 wire 尺寸由子字段上限派生：1 数组头 + 1 版本 + 1 kind + 34 + 34 + 259 = **330 字节**。

#### Buyer 签名域

```text
buyer_retrieval_signing_cbor = deterministic-CBOR([
  4,
  10,
  arbitration_claim_id,
  retrieval_nonce
])

buyer_retrieval_signature = SignMessage(BuyerKey, buyer_retrieval_signing_cbor)
```

`SignMessage` 是项目固定语义：对 exact signing CBOR 做一次 SHA-256，再输出 low-S DER ECDSA 签名。Buyer 绝不签 Claim ID 裸 bytes、nonce 裸 bytes、字符串拼接、hex、JSON、完整五元请求或仲裁交易 sighash。

nonce 由 Buye r**应用**用密码学安全随机源生成并显式传入 SDK。SDK 不生成、不保存、不去重 nonce；时间戳、自增序号、Claim ID 前缀与全零值都是非法 nonce。

#### Claim ID 复用

Claim ID 算法与 007 完全一致且不变：

```text
ArbitrationClaimID = SHA-256(deterministic-CBOR([4, 8, exact_claim_cbor]))
```

Claim ID 绑定 exact ClaimCBOR，进而绑定 pool source context、RefundTx、Buyer 签名的 exact TermsCBOR 与有序 content hashes，因此 Buyer 只凭本地 OpeningProof + 精确签名 003 就能得到相同 Claim ID——不需要 Seller Claim 签名、payload 或 Kind 9。

### Kind 11 · ArbitrationContentResponse（仲裁方 → 买方）

wire 真值：`[4, 11, exact_arbitration_request_cbor, exact_arbitration_response_cbor]`

```text
ArbitrationContentResponse = [
  4,
  11,
  exact_arbitration_request_cbor,
  exact_arbitration_response_cbor
]
```

两个子文档都是 `bstr` 嵌入的持久化原文：

- `exact_arbitration_request_cbor`：仲裁托管库中保存的 exact canonical Kind 8，含 ClaimCBOR、SellerClaimSignature 与 ContentPayloadsCBOR；
- `exact_arbitration_response_cbor`：同一条记录中已持久化的 exact canonical Kind 9，含 Receipt 与 ArbiterReceiptSignature，Receipt 绑定同一 Claim ID。

外壳**不新增**第三条 Arbiter 签名，因为它不创造第二份托管真值：

```text
SellerClaimSignature    -> exact ClaimCBOR -> Buyer signed TermsCBOR -> ordered content hashes

ArbiterReceiptSignature -> exact ReceiptCBOR -> same Claim ID -> fee + Arbiter transaction signature

ContentPayloadsCBOR[i]  -> SHA-256 -> ordered content hashes[i]
```

Buyer 必须验证上述整条链：签名域严格为 deterministic-CBOR([4, 10, claim_id, nonce])，内嵌 ClaimCBOR 必须逐字节等于本地重建的 expected ClaimCBOR。Kind 11 只是把两份已签证据一次返回。payload 字节只在内嵌 Kind 8 中出现一次。响应不重复 claim_id、content_payloads_cbor、receipt_cbor、任何公钥、OpeningProof、FundingTx、PaymentAuthorizationHash 或 raw candidate，也绝不宣称 Seller 仲裁交易已广播、已上链或已最终结算。

最大 wire 尺寸由当前 Kind 8/9 上限派生：

```text
1 数组头 + 1 版本 + 1 kind
+ 5 字节 bstr 头 + MaxArbitrationRequestBytes   (16,843,609)
+ 3 字节 bstr 头 + MaxArbitrationResponseBytes  (568)
= 16,844,188 字节
```

若未来子上限变化，必须从实际常量重新派生并用测试重新钉死。

## 验证链

只有以下全部通过，Kind 11 才被接受：

1. strict deterministic 解码 Kind 10 及两份内嵌文档；
2. 从内嵌 Kind 8 Claim 重算的 Claim ID 同时等于 Kind 10 的 Claim ID 和 Kind 9 Receipt 的 Claim ID；
3. 从 Claim 池锁定脚本的固定角色顺序恢复 Buyer/Seller/Arbiter 公钥；
4. Buyer 对 `[4, 10, claim_id, nonce]` 的签名；
5. Buyer 对精确 003 TermsCBOR 的签名；
6. Seller 对精确 `[4, 8, claim_cbor]` 的签名；
7. payload 数量、顺序、大小、canonical 子 CBOR 与逐项 SHA-256；
8. Arbiter 对精确 `[4, 9, receipt_cbor]` 的签名;
9. 用 Receipt 费用重建 candidate 后验证仲裁交易签名;
10. 内嵌 ClaimCBOR **逐字节等于本地重建的 ClaimCBOR**（只比较 hash 不够）。

验收是时间无关的：过期报价、已过交付截止和已成熟退款都不会使仍处 retention 期内的已签托管证据失效。全程不需要假时钟或假区块高度。

Kind 11 只表达成功取回。NotFound、NotReady、Unauthorized、NonceReused、Gone、RateLimited 全部走应用错误通道；Kind 11 中不存在 optional status union。

## 008 明确不做的事

- 不存在 Buyer 仲裁关池、快速退款、强制 close、Buyer+Arbiter 合签关池交易或 Seller challenge window。Seller 从未提交 007 或记录已删除时，Buyer 等待 Seller 恢复或在 `nLockTime` 成熟后广播 002 的预签名 RefundTx。
- 不复用 Kind 6 `ContentDelivery`，不调用 `buyer.AcceptDelivery`：008 验收只返回 payload 加审计数据，不产生 005 PaymentUpdate，不签任何买方交易，不改 previous PaymentState，不构造任何关池交易。
- Claim ID 不是下载令牌：只携带 Claim ID 而无有效 Buyer 签名的请求永远拿不到内容。
- nonce 不是加密，也不代替 TLS：生产传输必须提供机密性、完整性和仲裁方 endpoint 身份认证。
