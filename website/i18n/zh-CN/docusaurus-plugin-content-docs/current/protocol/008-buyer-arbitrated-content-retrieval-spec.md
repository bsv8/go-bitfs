---
id: 008-buyer-arbitrated-content-retrieval-spec
title: 008 · 买方仲裁托管内容取回规范
---

# 008 · 买方仲裁托管内容取回规范

008 为现有 007 Seller 仲裁托管补齐 Buyer 取件路径。Seller 与 Buyer 无法直连、但二者均能连接 Arbiter 时，Seller 继续通过 Kind 8 把精确 payload bundle 托管给 Arbiter，Arbiter 按现有 Kind 9 完成付费仲裁回执；Buyer 使用自己可独立计算的 `ArbitrationClaimID` 定位托管记录，经 `SignWireDocument(1, 10, ...)` 统一签名鉴权后，接收 Arbiter 签名的 Kind 11：可交付分支通过 `content_payloads_id` 绑定 exact payload bundle，不可交付分支携带结构化原因。

这是 v1 一次性硬切换：Kind 10/11 只存在以下唯一形状。没有兼容 decoder、feature flag、双形状或按字段是否为空的猜测。

## Wire 文档

### Kind 10 · ContentRetrievalRequest（买方 → 仲裁方）

wire 真值：`[1, 10, content_retrieval_request_cbor, buyer_content_retrieval_request_signature]`

```text
ContentRetrievalRequest = [
  1,
  10,
  content_retrieval_request_cbor,
  buyer_content_retrieval_request_signature
]

content_retrieval_request_cbor = [
  arbitration_claim_id,
  retrieval_nonce
]
```

约束：

```text
arbitration_claim_id                      = bstr .size 32
retrieval_nonce                           = bstr .size 32   ; 禁止全零
buyer_content_retrieval_request_signature = bstr .size (1..256)
```

请求不携带任何其他字段：不重复 BuyerPublicKey、RefundTemplateTxID、PaymentAuthorizationID、OpeningProof、payment authorization 文档或 Claim 字节——仲裁方从签名文档内 Claim ID 对应的已存 Claim 恢复全部角色公钥。最大 wire 尺寸由子字段上限派生：1 数组头 + 1 版本 + 1 kind + (3 + 69) + (3 + 259) = **334 字节**。

#### Buyer 签名域

```text
WireSignatureInput(1, 10, content_retrieval_request_cbor)
  = deterministic-CBOR(["bitfs/wire-signature", 1, 10, content_retrieval_request_cbor])

buyer_content_retrieval_request_signature =
  SignWireDocument(BuyerKey, 1, 10, content_retrieval_request_cbor)
```

`SignWireDocument` 是项目固定语义：构造上述 typed 签名输入，做一次 SHA-256，再输出 low-S DER ECDSA 签名。Buyer 绝不签 Claim ID 裸 bytes、nonce 裸 bytes、字符串拼接、hex、JSON、完整四元 wire 报文或仲裁交易 sighash。

nonce 由 Buyer **应用**用密码学安全随机源生成并显式传入 SDK。SDK 不生成、不保存、不去重 nonce；时间戳、自增序号、Claim ID 前缀与全零值都是非法 nonce。

#### nonce 一次性与重放语义

`content_retrieval_request_id`（exact 请求文档的 SHA-256）与
`(arbitration_claim_id, retrieval_nonce)` 一一对应。仲裁方应用 MUST：

- 对每一条 `not_ready`、`custody_gone`、`available` 应答，在完成 Buyer 鉴权之后、
  签署之前原子占用 `(Claim ID, Nonce)`，并把首次签署的 Kind 11 持久化为该请求的唯一答案；
- 同一 `content_retrieval_request_id` 重放时原样重发第一份持久化的 Kind 11；
  此后的状态变化绝不能把已捕获的 `not_ready` 升级为下载授权；
- 每次收到 `not_ready` 后的重试都必须使用新 nonce（和新签名）；
- 把 `seller_arbitration_not_received` 作为唯一例外：没有 Claim 就无法鉴权，
  不占用任何状态；但此类查询必须限流，且不得泄露记录元数据；
- nonce 去重记录至少保留到托管记录删除为止；留存期满时，缓存的首次应答必须
  与内容一起删除。

#### Claim ID 复用

Claim ID 算法与 007 完全一致且不变：

```text
ArbitrationClaimID = SHA-256(exact_arbitration_claim_cbor)
```

Claim ID 绑定 exact claim 文档，进而绑定 pool source context、refund template raw bytes、Buyer 签名的 payment authorization 与有序 content hashes，因此 Buyer 只凭本地 OpeningProof + 精确签名的付款授权就能得到相同 Claim ID——不需要 Seller Claim 签名、payload 或 Kind 9。

### Kind 11 · ContentRetrievalResponse（仲裁方 → 买方）

Kind 11 是由判别值显式区分的双分支 union，由 Arbiter 通过 `SignWireDocument(1, 11, ...)` 签名。判别值位于 `content_retrieval_result_cbor` 内部并决定唯一合法的外层形状；不允许按字段 presence 或数组长度猜测。

```text
content_retrieval_result_cbor = [
  content_retrieval_request_id,   ; SHA-256(exact content_retrieval_request_cbor)
  result,                         ; 0 unavailable / 1 available
  branch_value
]
```

**Unavailable 分支**（`result = 0`，外层恰好四元，禁止携带 attachment）：

```text
ContentRetrievalResponse = [1, 11, result_cbor, arbiter_content_retrieval_result_signature]

branch_value = content_retrieval_unavailable_reason
             ; 0 seller_arbitration_not_received
             ; 1 seller_arbitration_not_ready
             ; 2 custody_gone
```

该分支不返回任何 Claim、角色公钥、payload 或记录元数据。托管记录不存在时仲裁方无法鉴权 Buyer：它对结构合法的 request ID 返回最小签名负面响应，并对随机查询做速率限制。一旦存在记录或可验证 tombstone，必须先完成 Buyer 鉴权。

**Available 分支**（`result = 1`，外层恰好五元，attachment 必须存在）：

```text
ContentRetrievalResponse = [1, 11, result_cbor, arbiter_content_retrieval_result_signature, content_payloads_cbor]

branch_value = content_payloads_id   ; SHA-256(exact content_payloads_cbor)
```

`content_payloads_id` 在不把最高约 16.8 MB payload 复制进签名预映像的前提下，绑定本次返回 bundle 的数量、顺序与原始字节。它不替代 Buyer 签名的付款授权中逐项的 `content_hashes_cbor`：前者证明"Arbiter 本次返回了哪一份 exact bundle"，后者证明"这些块是不是 Buyer 原先授权购买的内容"。

响应不重复 claim_id、receipt 字节、任何公钥、OpeningProof、资金交易或 raw candidate，也绝不宣称 Seller 仲裁交易已广播、已上链或已最终结算。Unauthorized、Malformed、RateLimited 与内部存储错误仍属于传输/应用错误通道，绝不伪装成结构合法的 unavailable 响应。

## 验证链

只有以下全部通过，Available Kind 11 才被接受：

1. strict deterministic 解码 Kind 10、result 文档及其唯一分支形状；
2. 签名的 `content_retrieval_request_id` 等于 Buyer 自己请求文档的 SHA-256；
3. Arbiter 签名经 `VerifyWireDocument(1, 11, ...)` 验证通过；
4. `content_payloads_id` 等于附件 payload bundle 的 SHA-256；
5. payload 数量、顺序、大小、canonical 子 CBOR 与逐项 SHA-256 与本地保存付款授权中的有序 hashes 完全一致。

验收是时间无关的：过期报价、已过交付截止和已成熟退款都不会使仍处 retention 期内的已签托管证据失效。全程不需要假时钟或假区块高度。

Unavailable 应答绝不意味着 Seller 永远不会仲裁，也不产生退款、关池或任何付款状态变化。

## 008 明确不做的事

- 不存在 Buyer 仲裁关池、快速退款、强制 close、Buyer+Arbiter 合签关池交易或 Seller challenge window。Seller 从未提交 007 或记录已删除时，Buyer 等待 Seller 恢复或在 `nLockTime` 成熟后广播 002 的预签名退款交易。
- 不复用 Kind 6 `ContentDelivery`，不调用 `buyer.AcceptDelivery`：008 验收只返回 payload 加审计数据，不产生 PaymentUpdate，不签任何买方交易，不改 previous PaymentState，不构造任何关池交易。
- Claim ID 不是下载令牌：只携带 Claim ID 而无有效 Buyer 签名的请求永远拿不到内容。
- nonce 不是加密，也不代替 TLS：生产传输必须提供机密性、完整性和仲裁方 endpoint 身份认证。
