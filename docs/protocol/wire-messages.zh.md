# BitFS Wire Protocol v1 统一报文规范

> 状态：现行实现真值。Go SDK（`protocol`/`wire`/`bitfs`/`pool`/`arbitration`/
> `buyer`/`seller`）与 `spec/v1/wire-messages.cddl` 与本文一一对应；
> 旧版报文体系已归档至 `spec/legacy/`。
>
> 本文定义 wire 的版本模型、报文外形、认证文档、签名域、ID 与命名规则。
> 买方、卖方、仲裁方的业务职责，001–008 的业务次序，2-of-3 资金池、累计付款、
> 仲裁费用、托管内容及关闭/退款规则均保持现有协议原意。

---

## 1. 设计结论

BitFS 对外只暴露一个协议版本：

```go
protocol.WireVersion = 1
```

不再定义或暴露 `pool.MultisigVersion`、`pool.MajorVersion`、
`arbitration.MajorVersion`、`contentProtocolVersion` 等平行版本常量。
底层交易库可以有自己的 module/release 版本，但它不是 BitFS wire 字段，也不是
BitFS 应用需要协商的第二个协议版本。

如果底层 MultisigPool 的变化影响以下任一项，BitFS 必须整体提升
`protocol.WireVersion`：

- 交易构造、序列号、locktime、输出顺序、金额或矿工费计算；
- 交易 sighash、签名合并或脚本语义；
- 已有 Kind 的 wire 字节、确定性重建结果或协议验收规则。

如果只是依赖库修复或实现优化，且上述协议可观察结果完全不变，则不提升
`WireVersion`。

新增独立 Kind 是加法扩展，不改变任何已有 Kind 的外形；旧 decoder 会把新 Kind
按 `unsupported_kind` 拒绝，只有双方都支持该 Kind 时才能交换对应报文。

本设计统一规定：

1. 所有完整 wire 报文都以 `[1, wire_kind, ...]` 开头。
2. `wire_kind` 使用 `1..13`，不再同时存在 wire Kind `3/4` 与内层 Kind `13/14`。
3. 认证 CBOR 文档只包含业务字段，不重复外层已经携带的版本和 Kind。
4. 普通消息签名通过唯一的 `SignWireDocument` 将外层版本、Kind 与 exact 认证文档纳入
   统一签名上下文，禁止跨协议、跨版本、跨 Kind 解释签名。
5. 大 payload 和交易原文作为 attachment 传输；认证文档直接或传递地绑定它们。
6. 交易签名继续覆盖原生交易 sighash，不为追求外形一致而增加没有语义价值的重复签名。

---

## 2. 三层模型

```text
Transport
  └── Packet{Kind, CBOR}                         路由与传输
        └── [wire_version, wire_kind, ...]       完整 wire 报文
              ├── authenticated_document_cbor   只包含业务字段的认证文档
              ├── signature                     普通消息签名或交易签名
              └── attachments                   payload、交易原文
```

### 2.1 完整 wire 报文

所有报文的前两个元素固定为：

```text
[1, wire_kind, ...]
```

外层 `1` 和 `wire_kind` 用于快速路由、尺寸限制、选择严格 decoder，并作为普通消息
签名的类型化上下文。认证子文档不再重复它们。encoder 固定注入外层版本和 Kind，
不接受调用方填写。

### 2.2 认证文档

认证文档只包含该对象的业务字段：

```text
authenticated_document_cbor =
  deterministic-CBOR([...authenticated_fields])
```

文档本身没有版本和 Kind。它只能出现在对应的 `[1, wire_kind, ...]` 完整报文中，
并由该 Kind 的严格 decoder 解释。

但是，不能在删除子文档中的版本和 Kind 后，继续只执行
`SignMessage(key, authenticated_document_cbor)`。那会使外层版本和 Kind 完全不受认证，
同一签名可能被换壳后交给另一个版本或 Kind 的 verifier。

普通消息签名统一走唯一 helper：

```text
WireSignatureInput(wire_version, wire_kind, document_cbor) =
  deterministic-CBOR([
    "bitfs/wire-signature", wire_version, wire_kind, document_cbor
  ])

SignWireDocument(private_key, wire_version, wire_kind, document_cbor) =
  SignMessage(private_key,
    WireSignatureInput(wire_version, wire_kind, document_cbor))

VerifyWireDocument(public_key, wire_version, wire_kind, document_cbor, signature) =
  VerifySignature(public_key,
    WireSignatureInput(wire_version, wire_kind, document_cbor), signature)

document_id = SHA-256(authenticated_document_cbor)
```

`WireSignatureInput` 的结果不是 wire 字段，也不持久化为第二份业务文档。统一 helper
只把外层上下文和 exact `document_cbor` 作为一个 bstr 包装；绝不解码并重新编码文档中的
业务字段，也不允许每种报文各写一套 signing-domain 拼装代码。

`SignMessage` 仍表示：对输入字节做一次 SHA-256，再生成 low-S DER ECDSA 签名。
对象 ID 只由对应业务 CBOR 计算，因此 `arbitration_claim_cbor` 与
`arbitration_claim_id` 等名称仍保持一一对应。

认证文档可以作为 exact evidence 嵌入后续报文，例如
`payment_authorization_cbor` 会进入 Kind 8 Claim。此时不需要把原 Kind 5 外壳一起嵌入；
Kind 8 的固定 schema 已声明该字段只能是 v1 Kind 5 payment authorization，verifier 必须
调用 `VerifyWireDocument(1, 5, payment_authorization_cbor, buyer_signature)`。
协议不提供脱离具体类型的 generic authenticated-document decoder。

由于 `document_id` 不重复编码版本和 Kind，它是版本及 Kind 命名空间内的 typed ID。
持久化索引必须使用具体 ID 类型，或使用 `(wire_version, wire_kind, document_id)` 复合键，
不得建立跨版本、跨 Kind 的无类型全局 32-byte ID 空间。

### 2.3 Attachment

以下对象可以留在认证文档之外：

- 大体积 `content_payloads_cbor`；
- 原始资金交易；
- 明确标注为非认证展示信息的字段。

Attachment 必须满足至少一种绑定方式：

1. 认证文档直接包含 attachment 的 SHA-256；
2. 认证文档引用的另一份已签文档包含逐项内容哈希；
3. attachment 本身是可独立验证的原始交易。

“不直接进入签名预映像”不等于“不验证”。

---

## 3. 命名规范

### 3.1 后缀只有一种含义

| 后缀 | 唯一含义 | 示例 |
|---|---|---|
| `_cbor` | 一份 exact deterministic CBOR 子文档 | `arbitration_claim_cbor` |
| `_id` | `SHA-256(corresponding_cbor)` | `arbitration_claim_id` |
| `_wire_cbor` | 一份完整 `[1, kind, ...]` wire 报文的 exact bytes | `arbitration_request_wire_cbor` |
| `_wire_id` | `SHA-256(corresponding_wire_cbor)` | `arbitration_request_wire_id` |
| `_raw` | 非 CBOR 格式的原始序列化字节 | `refund_template_raw` |
| `_txid` | 按交易协议计算的 transaction ID，不是普通 SHA-256 文档 ID | `refund_template_txid` |
| `_hash` | 内容摘要，不承担协议对象身份 | `seed_hash`、`content_hash` |
| `_signature` | 字段名中必须同时体现签名人和被签对象 | `seller_arbitration_claim_signature` |

因此禁止以下模糊命名：

```text
terms_cbor_hash       // 应改成具体对象的 *_id
request_hash          // 不清楚是内层文档还是完整 wire
signature             // 不清楚签名人、签名对象和签名算法语义
raw_cbor              // raw 与 cbor 语义重叠
```

### 3.2 CBOR 与 ID 必须词根完全对齐

只有被 wire 报文或其他协议对象实际引用的 ID 才是协议对象，并各自拥有
独立的 Go named type（见 `protocol/ids.go`）：

```text
file_quote_terms_cbor          -> file_quote_terms_id            （进入 Kind 5）
payment_authorization_cbor     -> payment_authorization_id       （Kind 6/7 与查找键）
arbitration_claim_cbor         -> arbitration_claim_id           （Kind 9/10 路由键）
content_retrieval_request_cbor -> content_retrieval_request_id   （绑定 Kind 11 两分支）
content_payloads_cbor          -> content_payloads_id            （Kind 11 available 附件绑定）
```

未被任何对象引用的派生文档哈希——例如 `content_delivery_cbor`、
`arbitration_receipt_cbor`、`content_retrieval_result_cbor` 自身的 SHA-256——
不是协议对象，不进入规范命名空间，也不定义对应的 Go named type；应用需要时
可以自行计算，但不得将其当作跨报文的引用键。

特别地，仲裁链只使用：

```text
arbitration_claim_id = SHA-256(arbitration_claim_cbor)
```

不能再把它定义为“某个临时重组 signing domain 的 hash”，也不能混用
`claim_hash`、`claim_cbor_hash`、`arbitration_request_id` 等近义词。

### 3.3 其他统一命名

- 公钥统一使用 `*_public_key`，不混用 `pubkey` / `pub_key` / `public_key`；
- 金额统一使用 `*_satoshis`，不混用 `*_sat` / `*_amount`；
- Unix 秒统一使用 `*_unix_seconds`；
- 非 CBOR 原始序列化统一使用“对象词根 + `_raw`”，例如
  `refund_template_raw`、`funding_transaction_raw`；
- 普通消息签名使用 `role + document + signature`；
- 交易签名必须含 `transaction_signature`，避免与普通消息签名混淆；
- 完整报文类型使用 `Message`，认证子文档不再使用含义宽泛的 `Terms`，除非它确实只表达条款。

---

## 4. Wire Kind 注册表

| Kind | 统一名称 | 方向 | 业务规格 |
|---:|---|---|---|
| 1 | `FileQuote` | Seller → Buyer | 001 |
| 2 | `RefundPresignRequest` | Buyer → Seller | 0201 |
| 3 | `RefundPresignResponse` | Seller → Buyer | 0202 |
| 4 | `FundingTransactionDelivery` | Buyer → Seller | 0203 |
| 5 | `ContentRequest` | Buyer → Seller | 003 |
| 6 | `ContentDelivery` | Seller → Buyer | 004 |
| 7 | `PaymentUpdate` | Buyer → Seller | 005 |
| 8 | `ArbitrationRequest` | Seller → Arbiter | 007 |
| 9 | `ArbitrationResponse` | Arbiter → Seller | 007 |
| 10 | `ContentRetrievalRequest` | Buyer → Arbiter | 008 |
| 11 | `ContentRetrievalResponse` | Arbiter → Buyer | 008 |
| 12 | `PoolCloseRequest` | Buyer → Seller | 006 |
| 13 | `PoolCloseResponse` | Seller → Buyer | 006 |

002 开池与 006 关池都在 wire 层定义买卖双方交换的交易材料；OpeningProof 和
池 checkpoint 仍是应用侧本地证据结构，不是 wire Kind。

### 4.1 十三种完整 wire 外壳

```text
Kind 1  = [1, 1,
  file_quote_terms_cbor, seller_public_key,
  seller_file_quote_terms_signature]

Kind 2  = [1, 2,
  refund_template_raw,
  buyer_public_key, seller_public_key, arbiter_public_key,
  miner_fee_rate_satoshis_per_kilobyte,
  buyer_refund_transaction_signature]

Kind 3  = [1, 3,
  refund_template_txid, seller_refund_transaction_signature]

Kind 4  = [1, 4,
  refund_template_txid, funding_transaction_raw]

Kind 5  = [1, 5,
  payment_authorization_cbor,
  buyer_payment_authorization_signature]

Kind 6  = [1, 6,
  content_delivery_cbor,
  seller_content_delivery_signature,
  content_payloads_cbor]

Kind 7  = [1, 7,
  payment_authorization_id,
  buyer_payment_transaction_signature]

Kind 8  = [1, 8,
  arbitration_claim_cbor,
  seller_arbitration_claim_signature,
  content_payloads_cbor]

Kind 9  = [1, 9,
  arbitration_receipt_cbor,
  arbiter_arbitration_receipt_signature]

Kind 10 = [1, 10,
  content_retrieval_request_cbor,
  buyer_content_retrieval_request_signature]

Kind 11 unavailable = [1, 11,
  content_retrieval_result_cbor,
  arbiter_content_retrieval_result_signature]

Kind 11 available = [1, 11,
  content_retrieval_result_cbor,
  arbiter_content_retrieval_result_signature,
  content_payloads_cbor]

Kind 12 = [1, 12,
  refund_template_txid,
  unsigned_close_transaction_raw,
  buyer_close_transaction_signature]

Kind 13 = [1, 13,
  refund_template_txid,
  complete_close_transaction_raw]
```

完整外壳负责传输和严格分发；所有 `*_cbor` 认证文档的精确内容、ID 与签名对象在后文定义。

---

## 5. Kind 1 · FileQuote

### 5.1 认证条款

```text
file_quote_terms_cbor = deterministic-CBOR([
  seed_hash,
  buyer_public_key,
  seed_price_satoshis,
  full_block_price_satoshis,
  file_size_bytes,
  quote_expires_at_unix_seconds,
  supported_arbiter_public_keys_cbor,
  recommended_filename
])

file_quote_terms_id = SHA-256(file_quote_terms_cbor)

seller_file_quote_terms_signature =
  SignWireDocument(seller_private_key, 1, 1, file_quote_terms_cbor)
```

### 5.2 完整报文

```text
[1, 1,
  file_quote_terms_cbor,
  seller_public_key,
  seller_file_quote_terms_signature
]
```

`recommended_filename` 虽然是经过 sanitize 的非经济展示字段，但它是 Seller 提供的
内容描述，因此进入 `file_quote_terms_cbor` 并由 Seller 一起签名。sanitize 负责路径安全，
签名负责来源真实性，两者职责不同。Seller 必须先 sanitize，再编码和签名；Buyer 只验证
收到的字段已经满足同一 sanitize 规则，不能验签后静默改写。由于它进入条款，文件名不同的
两份报价具有不同的 `file_quote_terms_id`。`seller_public_key` 仍用于建立和验证报价签名身份。

---

## 6. Kind 2 · RefundPresignRequest

```text
[1, 2,
  refund_template_raw,
  buyer_public_key,
  seller_public_key,
  arbiter_public_key,
  miner_fee_rate_satoshis_per_kilobyte,
  buyer_refund_transaction_signature
]
```

`buyer_refund_transaction_signature` 是退款交易签名，不是普通
`SignMessage` 签名。接收方必须从 `refund_template_raw` 验证资金来源、角色顺序、
锁定脚本、金额、费率和退款条件；不另造一份重复的普通消息签名。

Kind 2 不再增加 `SignWireDocument`。Buyer 交易签名的验证输入并不只有
`refund_template_raw`：固定 ForkID transaction sighash 还绑定待花费资金池 source output
的 amount 与 locking script，而它们由 Kind 2 的其他字段唯一派生：

```text
[buyer_public_key, seller_public_key, arbiter_public_key]
  -> pool_output_locking_script

[refund_template_raw, miner_fee_rate_satoshis_per_kilobyte]
  -> pool_output_satoshis

[refund_template_raw, pool_output_locking_script, pool_output_satoshis]
  -> buyer_refund_transaction_signature
```

Seller 必须先用全部 Kind 2 字段重建并验证这组 source context，再验 Buyer 交易签名，
最后才允许生成 Seller 交易签名。因此任意替换角色公钥、费率或退款模板，都会造成规范
重建不一致或 Buyer 交易签名验证失败。

这条结论带有严格前提：Kind 2 将来若增加一个既不能从退款交易/source context 推导，
也不进入 transaction sighash 的业务字段，就不能继续依赖现有交易签名；届时必须删除该
冗余字段，或新增独立的 Buyer 认证文档和 `SignWireDocument`。

保持现有业务原意：此时不传 FundingTransaction，必须先取得 Seller 的退款交易签名。

---

## 7. Kind 3 · RefundPresignResponse

```text
[1, 3,
  refund_template_txid,
  seller_refund_transaction_signature
]
```

```text
ValidateRefundTemplate(refund_template_raw)

refund_template_txid =
  ParseTransaction(refund_template_raw).TxID().CloneBytes()
```

这里不存在第二份退款模板字节。`refund_template_raw` 就是 Kind 2 携带并由
OpeningProof 原样保存的规范未签名退款交易：
资金池角色签名与交易原文分离，input unlocking script 必须为空。只有通过固定 builder
逐字段重建和逐字节 canonical 校验后，才允许对同一份 `refund_template_raw` 调用固定
交易库的 `TxID().CloneBytes()`。

`refund_template_txid` 必须由 Seller 从已验证的 Kind 2 重新派生，不能由调用方填写。
`refund_template_raw` 与 `refund_template_txid` 使用同一词根，后者是前者通过固定
交易 TxID 算法得到的派生 ID，而不是第二份模板。
`seller_refund_transaction_signature` 仍是退款交易 sighash 签名。

原 CBOR 内层 Kind `13` 删除；wire Kind `3` 是唯一报文类型编号。

---

## 8. Kind 4 · FundingTransactionDelivery

```text
[1, 4,
  refund_template_txid,
  funding_transaction_raw
]
```

`funding_transaction_raw` 包含资金交易自身所需的交易签名。Seller 必须验证其交易 ID、
资金池输出索引、金额和 locking script 与已保存的开池证据一致。

原 CBOR 内层 Kind `14` 删除；wire Kind `4` 是唯一报文类型编号。

---

## 9. Kind 5 · ContentRequest

### 9.1 付款授权文档

003 条款结构的实际协议语义是“Buyer 的最终付款授权”，因此统一命名为
`payment_authorization`：

```text
payment_authorization_cbor = deterministic-CBOR([
  file_quote_terms_id,
  refund_template_txid,
  payment_sequence,
  seller_amount_after_satoshis,
  content_hashes_cbor,
  delivery_deadline_unix_seconds
])

payment_authorization_id = SHA-256(payment_authorization_cbor)

buyer_payment_authorization_signature =
  SignWireDocument(buyer_private_key, 1, 5, payment_authorization_cbor)
```

### 9.2 完整报文

```text
[1, 5,
  payment_authorization_cbor,
  buyer_payment_authorization_signature
]
```

报价引用键统一命名为 `file_quote_terms_id`，付款授权引用键统一命名为
`payment_authorization_id`：两者都是对应认证文档的 SHA-256，只使用这一套
对象命名，不保留任何哈希式旧名。

---

## 10. Kind 6 · ContentDelivery

### 10.1 交付认证文档

```text
content_delivery_cbor = deterministic-CBOR([
  payment_authorization_id
])

seller_content_delivery_signature =
  SignWireDocument(seller_private_key, 1, 6, content_delivery_cbor)
```

### 10.2 完整报文

```text
[1, 6,
  content_delivery_cbor,
  seller_content_delivery_signature,
  content_payloads_cbor
]
```

payload 不直接进入签名预映像，绑定链保持现有业务原意：

```text
Seller signature
  -> content_delivery_cbor
  -> payment_authorization_id
  -> payment_authorization_cbor
  -> ordered content_hashes_cbor
  -> SHA-256(content_payloads[i])
```

统一 Kind 6 签名上下文认证的是精确 `content_delivery_cbor`，不改变交付内容
和付款授权的对应关系。

---

## 11. Kind 7 · PaymentUpdate

```text
[1, 7,
  payment_authorization_id,
  buyer_payment_transaction_signature
]
```

`buyer_payment_transaction_signature` 继续覆盖 Buyer/Seller 根据 OpeningProof、previous
PaymentState 和 `payment_authorization_cbor` 本地确定性重建的状态交易 sighash。

Kind 7 不增加普通消息签名：付款意图已经由 Kind 5 的 Buyer 签名表达，花费授权由本字段的
交易签名表达。`payment_authorization_id` 是查找精确 Kind 5 的内容寻址键。

---

## 12. Kind 8 · ArbitrationRequest

### 12.1 仲裁 Claim 文档

```text
arbitration_claim_cbor = deterministic-CBOR([
  pool_output_satoshis,
  pool_output_locking_script,
  refund_template_raw,
  payment_authorization_cbor,
  buyer_payment_authorization_signature
])

arbitration_claim_id = SHA-256(arbitration_claim_cbor)

seller_arbitration_claim_signature =
  SignWireDocument(seller_private_key, 1, 8, arbitration_claim_cbor)
```

`arbitration_claim_cbor` 本身就是 Claim 的唯一业务字节和 ID 来源。Seller 通过全局唯一的
`SignWireDocument(..., 1, 8, arbitration_claim_cbor)` 认证它，不再为 Claim 单独定义一套
字段重组算法：

```text
arbitration_claim_id = SHA-256(arbitration_claim_cbor)
seller_arbitration_claim_signature =
  SignWireDocument(seller_private_key, 1, 8, arbitration_claim_cbor)
```

因此 `arbitration_claim_cbor` 与 `arbitration_claim_id` 在名称、字节来源和验证路径上
完全对应。

### 12.2 完整报文

```text
[1, 8,
  arbitration_claim_cbor,
  seller_arbitration_claim_signature,
  content_payloads_cbor
]
```

`content_payloads_cbor` 继续通过 Buyer 已签的 `payment_authorization_cbor` 中的有序
content hashes 传递绑定，不重复加入 Claim。

---

## 13. Kind 9 · ArbitrationResponse

### 13.1 仲裁 Receipt 文档

```text
arbitration_receipt_cbor = deterministic-CBOR([
  arbitration_claim_id,
  arbiter_amount_satoshis,
  arbiter_payment_transaction_signature
])

arbiter_arbitration_receipt_signature =
  SignWireDocument(arbiter_private_key, 1, 9, arbitration_receipt_cbor)
```

`arbiter_payment_transaction_signature` 是对本地重建仲裁付款交易的原生交易签名；
`arbiter_arbitration_receipt_signature` 是对 Claim ID、仲裁金额和交易签名字节的普通
消息签名。两者职责继续严格分离。

### 13.2 完整报文

```text
[1, 9,
  arbitration_receipt_cbor,
  arbiter_arbitration_receipt_signature
]
```

Receipt 有意保持为无版本、无 Kind 的三元业务子文档。版本和 Kind 只存在于完整 wire
外层，并由统一 `SignWireDocument(..., 1, 9, arbitration_receipt_cbor)` 纳入签名上下文。

---

## 14. Kind 10 · ContentRetrievalRequest

### 14.1 取件请求文档

```text
content_retrieval_request_cbor = deterministic-CBOR([
  arbitration_claim_id,
  retrieval_nonce
])

content_retrieval_request_id =
  SHA-256(content_retrieval_request_cbor)

buyer_content_retrieval_request_signature =
  SignWireDocument(buyer_private_key, 1, 10, content_retrieval_request_cbor)
```

### 14.2 完整报文

```text
[1, 10,
  content_retrieval_request_cbor,
  buyer_content_retrieval_request_signature
]
```

保持现有业务原意：

- `retrieval_nonce` 为 32 字节、禁止全零，由 Buyer 应用使用 CSPRNG 生成；
- Claim ID 用于查找托管记录，不是 bearer token；
- Buyer 公钥从 Claim 的资金池 locking script 恢复，不在请求中重复携带；
- nonce 不加入其他不需要交互式重放防护的报文。

### 14.3 nonce 一次性与重放语义（规范性）

`content_retrieval_request_cbor` 的内容寻址 ID 与 `(arbitration_claim_id,
retrieval_nonce)` 一一对应，因此 Arbiter 以请求 ID 为键执行以下规则：

1. **占用**：`not_ready`、`custody_gone`、`available` 三种应答都必须在完成
   Buyer 鉴权之后原子占用该 `(Claim ID, Nonce)`，并把经事务选中的那份
   Kind 11 持久化为该请求的唯一答案；验签失败的请求绝不占用。候选应答可以
   在事务外提前签署，但"custody 状态复核 + nonce 唯一键 + exact 首次响应
   插入"必须是同一个原子提交——只有事务选中的响应才成为协议答案，不需要
   独立的 pending/reservation 状态，并发产生的未提交签名直接丢弃。提交时
   必须复核 custody 状态：期间 Kind 9 落地则 NotReady 候选作废并按最新完整
   状态重建 Available；期间内容被 retention 删除则改答 `custody_gone`。
2. **重放**：同一 `content_retrieval_request_id` 重放时原样重发第一次持久化
   的 Kind 11。记录状态随后发生任何变化（Kind 9 落地、留存期删除）都不得
   升级或重新评估已应答的请求：曾经捕获的 `not_ready` 请求永远不会再变成
   下载授权。
3. **新 nonce**：Buyer 收到 `not_ready` 后必须生成新 nonce 和新 Kind 10 签名
   重试；旧 nonce 不再产生任何新的可交付结果。
4. **唯一例外** `seller_arbitration_not_received`：没有 Claim 就无法恢复
   Buyer 公钥完成鉴权。该分支不占用 nonce、不持久化响应；endpoint 必须对
   随机 Claim ID 查询限流，且不得返回任何记录元数据（见 §15.6）。
5. **retention 是幂等保证的唯一终止例外**。首次响应的重放幂等只在 custody
   retention 生命周期内成立；nonce 去重记录至少保留到对应 custody record
   删除，留存期满安全删除内容时，已持久化的首次响应必须与内容一起删除，
   且提交路径必须在同一原子事务内复核 retention 状态——删除落地后，相同
   请求只能得到签名的 `custody_gone`，绝不允许复活已删除内容。

---

## 15. Kind 11 · ContentRetrievalResponse

Kind 11 是 Kind 10 的完整 wire 响应，不再只表达成功。它是一个由 `result` 显式判别的
两分支 union：

```text
content_retrieval_result =
  0  unavailable
  1  available
```

- `unavailable`：Arbiter 当前没有可向 Buyer 交付的托管内容；
- `available`：Arbiter 已完成允许取回内容所需的内部状态转换，直接返回文件块。

两种响应都绑定同一个 `content_retrieval_request_id`，并由 Arbiter 通过 Kind 11
`SignWireDocument` 签名。不存在“NotFound 只走未签名 HTTP error，而成功才是 wire”的
不对称设计。

### 15.1 Unavailable 原因

现有业务实际存在三种不可交付原因，不能全部错误描述成“从未收到 Seller 仲裁”：

```text
content_retrieval_unavailable_reason =
  0  seller_arbitration_not_received
  1  seller_arbitration_not_ready
  2  custody_gone
```

- `seller_arbitration_not_received`：不存在该 Claim ID 的 Kind 8 托管记录；
- `seller_arbitration_not_ready`：已收到并持久化 Kind 8，但 Kind 9 尚未完成和持久化；
- `custody_gone`：曾有完整托管记录，但已按公开 retention policy 删除内容。

`custody_gone` 只有在应用保留最小 tombstone 状态，既能区分“从未收到”和“曾有但
已删除”，又保留验证 Buyer 所需的 Claim/角色公钥关联时才能返回；如果彻底删除全部状态，
就只能诚实返回
`seller_arbitration_not_received`，不能凭空声称曾经托管。

### 15.2 Unavailable 响应

```text
content_retrieval_result_cbor = deterministic-CBOR([
  content_retrieval_request_id,
  0,
  content_retrieval_unavailable_reason
])

arbiter_content_retrieval_result_signature =
  SignWireDocument(arbiter_private_key, 1, 11, content_retrieval_result_cbor)
```

完整 wire：

```text
[1, 11,
  content_retrieval_result_cbor,
  arbiter_content_retrieval_result_signature
]
```

该分支不携带空 payload、`null` Kind 8/9、虚构 Claim、optional attachment 或占位 hash。
Buyer 验证 request ID 和 Arbiter 签名后，把结果解释为“本次查询当前不可交付”；它不是
Seller 永远不会仲裁的证明，也不产生退款、关池或付款状态变化。

### 15.3 Available payload ID

```text
content_payloads_id =
  SHA-256(content_payloads_cbor)
```

`content_payloads_id` 绑定本次返回的 exact deterministic CBOR，包括文件块的数量、顺序和
每个块的原始字节。它使 Arbiter 可以签署固定大小的结果文档，而不必把大 payload 复制进
签名预映像。它不替代 `payment_authorization_cbor` 中逐块的 `content_hashes_cbor`：前者
证明“Arbiter 本次返回了哪一份 exact payload 集合”，后者证明“这些块是不是 Buyer 原先
授权购买的内容”。

### 15.4 Available 响应（包含文件块）

```text
content_retrieval_result_cbor = deterministic-CBOR([
  content_retrieval_request_id,
  1,
  content_payloads_id
])

arbiter_content_retrieval_result_signature =
  SignWireDocument(arbiter_private_key, 1, 11, content_retrieval_result_cbor)
```

完整 wire：

```text
[1, 11,
  content_retrieval_result_cbor,
  arbiter_content_retrieval_result_signature,
  content_payloads_cbor
]
```

`content_payloads_cbor` 就是 Buyer 请求取回的文件块，不再包装或附带完整 Kind 8/9。
Kind 8/9 是 Seller 与 Arbiter 之间的仲裁协议证据；Arbiter 可以继续持久化并在内部用它们
决定内容是否可取回，但它们不是 Buyer 完成内容恢复所需的 wire 数据。

Buyer 收到 Available 后，直接解码 `content_payloads_cbor`，再按自己保存的
`payment_authorization_cbor` 所承诺的有序 content hash 逐块验证。

Buyer 必须同时验证：

1. `content_retrieval_request_id` 等于自己保存的 exact Kind 10 认证文档 ID；
2. Arbiter 对 `content_retrieval_result_cbor` 的普通消息签名；
3. `content_payloads_id` 等于 exact `content_payloads_cbor` 的 SHA-256；
4. payload 数量、顺序和每个文件块的 hash 与本地保存的
   `payment_authorization_cbor` 完全一致。

Arbiter 只签含两个 32 字节 ID 的小文档，不把最高约 16.8 MB 的 payload 复制进签名
预映像；`content_payloads_id` 仍使签名精确绑定本次返回的完整 payload bytes。

### 15.5 两个分支的严格解码

Kind 11 不是按 array 长度猜测旧/新格式：decoder 必须先严格解码
`content_retrieval_result_cbor` 的 `result`，再选择唯一分支：

| `result` | result CBOR 长度 | 完整 wire 长度 | attachments |
|---:|---:|---:|---|
| `0 unavailable` | 3 | 4 | 无 |
| `1 available` | 3 | 5 | `content_payloads_cbor` |

任何未知 result、错误数组长度、Unavailable 携带 attachment、Available 缺少 attachment、
attachment ID 不匹配或 trailing field 都必须拒绝，不允许 presence guessing。

### 15.6 负面响应的鉴权边界

当 `seller_arbitration_not_received` 为真时，Arbiter 没有 Claim，也就无法从 pool locking
script 恢复 Buyer 公钥验证 Kind 10。这是数据依赖决定的事实，不能伪装成“已经完成 Buyer
鉴权”。此时 Arbiter 可以对结构合法的 request ID 签署不含任何内容的负面响应，但必须：

- 不返回任何 Claim、角色公钥、payload 或记录元数据；
- 对随机 Claim ID 查询做速率限制，防止把 Arbiter 变成无限签名/查询服务；
- 不把负面响应解释成 Buyer 身份已经验证；
- 一旦完整记录或可验证 tombstone 存在，必须先从 Claim/保留的角色关联恢复 Buyer 公钥
  并验证 Kind 10，才允许返回
  `not_ready`、`gone` 的受保护状态或 `available` 内容。

`Unauthorized`、Malformed、RateLimited 和内部存储错误仍属于 transport/application error，
不能伪装成结构合法的 `unavailable` 响应。`not_received / not_ready / gone` 则是 Kind 11
内经过 Arbiter 签名的正常协议结果。

## Kind 12 / 13 · 006 协商关池

Kind 12 是 Buyer 发给 Seller 的固定五元数组；`refund_template_txid` 是首个业务字段，
`unsigned_close_transaction_raw` 是最终序号的未签名关闭交易，
`buyer_close_transaction_signature` 是买方对该交易的分离式交易签名。该签名覆盖
MultisigPool 交易 sighash，不是 `SignWireDocument` 消息签名。

Kind 13 是 Seller 返回 Buyer 的固定四元数组。`refund_template_txid` 仍是首个业务字段；
`complete_close_transaction_raw` 是包含买卖双方签名的完整交易原文。两个 Kind 的
交易原文各不得超过 65536 字节；交易解析器在分配交易对象前检查 CompactSize
数量与脚本长度，避免短报文声明巨量元素。严格 decoder 只验证 CBOR 外形、字段
类型与关联 ID 的长度/非零；Seller 和 Buyer 的角色
API 分别按本地 OpeningProof 验证池归属、candidate 与交易签名。Artifact 本身不声称
节点已接受或确认交易，广播仍由应用负责。

Go 与 TypeScript 的交易解析器目前各对输入和输出设置 10,000 个元素的实现资源
上限；该上限适用于包括 funding 在内的所有传入交易，因此超过上限的链上有效
交易也不能作为本 SDK 的开池证据。它是当前实现能力边界，不是比特币共识规则。

---

## 16. 完整签名矩阵

| 对象 | 签名人 | 精确签名输入 | 类型 |
|---|---|---|---|
| `file_quote_terms_cbor` | Seller | `WireSignatureInput(1, 1, file_quote_terms_cbor)` | `SignWireDocument` |
| refund transaction | Buyer | refund transaction sighash | 交易签名 |
| refund transaction | Seller | refund transaction sighash | 交易签名 |
| close transaction | Buyer | unsigned close transaction sighash | 交易签名 |
| close transaction | Seller | unsigned close transaction sighash | 交易签名 |
| `payment_authorization_cbor` | Buyer | `WireSignatureInput(1, 5, payment_authorization_cbor)` | `SignWireDocument` |
| `content_delivery_cbor` | Seller | `WireSignatureInput(1, 6, content_delivery_cbor)` | `SignWireDocument` |
| payment transaction | Buyer | rebuilt transaction sighash | 交易签名 |
| `arbitration_claim_cbor` | Seller | `WireSignatureInput(1, 8, arbitration_claim_cbor)` | `SignWireDocument` |
| arbitration payment transaction | Arbiter | rebuilt transaction sighash | 交易签名 |
| `arbitration_receipt_cbor` | Arbiter | `WireSignatureInput(1, 9, arbitration_receipt_cbor)` | `SignWireDocument` |
| `content_retrieval_request_cbor` | Buyer | `WireSignatureInput(1, 10, content_retrieval_request_cbor)` | `SignWireDocument` |
| `content_retrieval_result_cbor` | Arbiter | `WireSignatureInput(1, 11, content_retrieval_result_cbor)` | `SignWireDocument` |

统一规则不是“每个报文都额外签一次”，而是：

- 普通业务声明的 CBOR 只含业务字段，统一 helper 把 domain/version/kind 纳入签名输入；
- 花费授权签原生交易 sighash；
- 一个签名只承担一种清楚命名的责任。

---

## 17. ID 与证据链

```text
file_quote_terms_cbor
  └── SHA-256 -> file_quote_terms_id
        └── payment_authorization_cbor
              └── SHA-256 -> payment_authorization_id
                    ├── content_delivery_cbor
                    ├── Kind 7 payment lookup
                    └── arbitration_claim_cbor
                          └── SHA-256 -> arbitration_claim_id
                                ├── arbitration_receipt_cbor
                                └── content_retrieval_request_cbor
                                      └── SHA-256 -> content_retrieval_request_id
                                            └── content_retrieval_result_cbor
```

Kind 11 的 Available 分支另外绑定 exact payload：

```text
content_payloads_cbor
  └── SHA-256 -> content_payloads_id
        └── content_retrieval_result_cbor
```

`content_retrieval_request_id` 绑定请求，`content_payloads_id` 绑定响应载荷；两者分别阻止
请求—响应错配和 payload 替换。

---

## 18. 严格编码与验证规则

所有 encoder/decoder 必须遵守：

1. RFC 8949 core deterministic CBOR；
2. 只允许 definite-length array/bstr；
3. 禁止 tag、float、map、未声明的 simple value 和 trailing bytes；
4. 非 union 数组长度固定；显式 union 必须先读 discriminator，再按该分支的固定长度解码，
   不允许按字段 presence 或数组长度猜测旧/新 shape；
5. 解码后按唯一 encoder 重编码，必须与输入逐字节相等；
6. 先检查 wire 最大尺寸，再分配或深度解析；
7. 所有 exact byte slice 在 API 边界深拷贝；
8. 所有普通消息签名先用外层版本、Kind 和 exact 子文档重建唯一
   `WireSignatureInput`，再验证 DER、low-S 与公钥角色；
9. hash/ID 使用不同的 Go named type，禁止把任意 `[32]byte` 静默互换；
10. 新版本必须使用新 `WireVersion`，同一版本内禁止兼容 decoder 或字段 presence guessing。

历史上未上线的旧版本迭代目录已移动到 `spec/legacy/` 归档；现行唯一
CDDL 真值是 `spec/v1/wire-messages.cddl`。

---

## 19. 明确保留的业务原意

本设计没有改变以下业务规则：

- 三方角色和 `[Buyer, Seller, Arbiter]` 固定公钥顺序；
- 2-of-3 MultisigPool 的交易模型；
- 先取得双方退款签名，再公开 FundingTransaction；
- `refund_template_txid` 是资金池统一关联 ID；
- 一个 003 payment sequence 原子授权一个有序内容批次；
- 004 payload 通过 003 的有序 content hashes 绑定；
- 005 只传 authorization ID 与 Buyer 交易签名，交易由双方本地重建；
- 007 由 Seller 提交 Claim/payload，Arbiter 验证、托管、计费并独立重建交易；
- 仲裁费用是 Arbiter 状态交易中的正数绝对分配；
- 008 对“不可交付/可交付”都返回 Arbiter 签名的 Kind 11；可交付分支只取回托管内容，
  不替 Buyer 关池，不产生 005，不声明交易已经上链；
- 006 关池通过 Kind 12/13 交换关池请求和完整关闭交易，报文定义与开池一起归属 002；
- 广播、数据库、retention、TLS、队列和重试策略仍属于应用层。

---

## 20. 协议结构之外的业务建议（非规范）

以下建议不进入上面的 v1 报文结构，实施前应单独做业务决策。

### 20.1 Kind 10 重试与 nonce

重试与重放语义已经是 §14.3 的规范性规则：三种可鉴权分支原子占用 nonce 并
持久化首次应答、同请求重放原样返回、`not_ready` 之后必须换新 nonce、
`not_received` 是不占用的唯一例外但仍须限流。

以下仍是开放的业务建议，实施前需单独决策：

- 为请求增加应用层短时有效期，避免 nonce 记录永久保存；
- 如果未来取件会扣费或产生一次性副作用，再升级为 Arbiter 发放 server challenge。

这些变化涉及计费和存储语义，因此不在本结构稿中直接加入 `expires_at` 或 server nonce。

### 20.2 Kind 11 与传输机密性

新增 Arbiter 响应签名只解决来源、完整性和请求—响应绑定，不提供内容机密性。
Kind 11 仍必须通过 TLS 或等价的、验证 Arbiter 身份的安全传输发送。

---

## 21. 落地边界

这是上线前一次性 hard switch，不提供旧/新双写、兼容 decoder、版本自动探测或 alias：

1. 先冻结本文件与新的 `spec/v1/*.cddl`；
2. 建立唯一 `protocol.WireVersion = 1`，删除其他对外协议版本常量；
3. 统一 Kind、字段、Go 类型、函数和错误消息命名；
4. 先生成每个认证文档、ID、签名域和完整 wire 的 golden fixtures；
5. 再修改 encoder/decoder、workflow 和验证链；
6. 添加跨协议域、跨版本、跨 Kind、内外 Kind 不一致、attachment 替换、请求/响应错配测试；
7. 最后更新现行协议文档与网站，删除所有“v4 上线前 hard switch 历史”作为当前规范的表述。

在 v1 冻结之后，任何改变 wire shape、签名对象、ID 算法、交易重建或验收语义的修改，
都必须提升 `protocol.WireVersion`。

---

## 参考设计原则

- [RFC 8949 · Deterministically Encoded CBOR](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2)
- [RFC 9052 · COSE Structures and Process](https://www.rfc-editor.org/rfc/rfc9052.html)
- [BIP 340 · Domain Separation](https://bips.dev/340/)
- [RFC 9175 · Secure Request-Response Binding](https://www.rfc-editor.org/rfc/rfc9175.html#section-4)
