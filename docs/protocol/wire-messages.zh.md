# BitFS v4 报文体系总览（买方 / 卖方 / 仲裁方）

本文基于核心代码整理：`wire/wire.go`（报文分发）、`bitfs/quote.go` 与 `bitfs/content.go`（001–004）、
`pool/types.go` 与 `pool/cbor.go`（002/005）、`arbitration/workflow.go`（007）、
`buyer/workflow.go` / `seller/workflow.go`（角色工作流），并与 `spec/v4/*.cddl` 对照。

---

## 1. 总体模型

### 1.1 三个角色

| 角色 | 包 | 职责 |
|---|---|---|
| 买方 Buyer | `buyer/workflow.go` | 验收报价、发起开池、请求内容、验收交付、签署累计付款 |
| 卖方 Seller | `seller/workflow.go` | 签发报价、预签退款、验收资金交易、交付内容、验收付款、发起仲裁 |
| 仲裁方 Arbiter | `arbitration/workflow.go` | 验证证据后为卖方候选状态交易追加签名（只签名，不构造、不广播交易） |

三方公钥构成 2-of-3 多签资金池（MultisigPool v4）。任何两方合作即可推进或关闭资金池，
这正是"正常走买卖双方、纠纷走仲裁"的密码学基础。

### 1.2 报文分层的三个层次

```
传输层选择 Kind ──► Packet{Kind, CBOR}          （wire/wire.go，Kind 不进入签名字节）
                       │
                       ▼
              规范确定性 CBOR 文档               （真正被签名/验证的字节，严格 canonical 校验）
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   bitfs 包         pool 包       arbitration 包
  (001/003/004)   (002/005)        (007)
```

关键原则：

1. **Packet 信封不签名**。`Kind` 只是传输层路由标签；签名永远覆盖内层规范 CBOR 字节。
2. **所有解码器都是严格的**：定长数组、禁用 CBOR tag、禁用不定长编码、解码后重新编码必须逐字节相等（deterministic round-trip 校验）。
3. **签名与原文分离传输**（detached signature）：交易里不含角色签名，签名作为独立字段传递，由接收方合并。
4. **单一真值**：`RefundTemplateTxID`（预签名退款交易的 txid）是整个资金池的统一关联 ID，
   绝不在报文里重复携带可由其他字段推导的值。

### 1.3 报文与规格步骤对照

| wire.Kind | 常量名 | 规格 | 方向 | Go 类型 |
|---:|---|---|---|---|
| 1 | `Quote` | 001 报价凭据 | 卖方 → 买方 | `*bitfs.SignedFileQuote` |
| 2 | `PoolRefundPresignRequest` | 0201 退款预签请求 | 买方 → 卖方 | `*pool.RefundPresignRequest` |
| 3 | `PoolRefundPresignResponse` | 0202 退款预签响应 | 卖方 → 买方 | `*pool.RefundPresignResponse` |
| 4 | `PoolFundingTxDelivery` | 0203 资金交易交付 | 买方 → 卖方 | `*pool.FundingTxDelivery` |
| 5 | `ContentRequest` | 003 内容请求（付款授权） | 买方 → 卖方 | `*bitfs.SignedContentRequest` |
| 6 | `ContentDelivery` | 004 内容交付 | 卖方 → 买方 | `*bitfs.SignedContentDelivery` |
| 7 | `CumulativePayment` | 005 累计付款更新 | 买方 → 卖方 | `*pool.PaymentUpdate` |
| 8 | `ArbitrationRequest` | 007 仲裁证据包 | 卖方 → 仲裁方 | `*arbitration.ArbitrationRequest` |
| 9 | `ArbitrationResponse` | 007 仲裁签名结果 | 仲裁方 → 卖方 | `*arbitration.ArbitrationResponse` |

> 注：002 在线上拆成 0201/0202/0203 三步；006（无条件关闭池）不产生新报文类型，
> 复用 `UnsignedPayment` + 双方签名在 API 层传递（见 §5）。

---

## 2. 报文流转全景

```mermaid
sequenceDiagram
    participant B as 买方 Buyer
    participant S as 卖方 Seller
    participant A as 仲裁方 Arbiter

    Note over B,S: 阶段一：报价（001）
    S->>B: Kind 1  SignedFileQuote（定价承诺）

    Note over B,S: 阶段二：开池（002 = 0201→0202→0203）
    B->>S: Kind 2  RefundPresignRequest（退款交易+买方签名）
    S->>B: Kind 3  RefundPresignResponse（卖方退款签名+关联ID）
    B->>S: Kind 4  FundingTxDelivery（资金交易原文）
    Note over B,S: 双方各自持有完整 OpeningProof，池开立

    Note over B,S: 阶段三：内容交换与滚动付款（003→004→005，可循环）
    loop 每个内容块
        B->>S: Kind 5  SignedContentRequest（付款授权）
        S->>B: Kind 6  SignedContentDelivery（内容+卖方签名）
        B->>S: Kind 7  PaymentUpdate（下一状态+买方签名）
    end

    Note over B,S,A: 阶段四：仲裁（007，仅纠纷时）
    S->>A: Kind 8  ArbitrationRequest（开池证据+授权+候选交易+卖方签名）
    A->>S: Kind 9  ArbitrationResponse（哈希回执+仲裁签名）
    Note over S: 卖方合并双方签名并广播

    Note over B,S: 阶段五：关闭（006，无新报文）
    B->>S: UnsignedPayment + 买方签名（API 层，立即关闭）
    S->>B: SignedPayment（补卖方签名，买方提交）
```

---

## 3. 各报文详解

以下每节给出：CBOR 编码布局（与 CDDL 一致）、Go 结构体字段含义、以及合理性分析。

通用约定：

- 所有公钥均为 33 字节压缩 secp256k1 公钥（`protocol.ValidateCompressedPubKey` 强制）。
- 所有签名均为 DER 编码，且与被签字节分离传输；被签字节统一做一次 SHA-256 得到摘要。
- `Hash32` 为固定 32 字节数组，且禁止全零（全零是"未设置"哨兵值，不得上线）。

---

### 3.1 Kind 1 · 报价凭据（001）— 卖方 → 买方

外层（`EncodeSignedFileQuote`，5 元数组，版本独立为 1）：

```
[1, terms_cbor, seller_pubkey, terms_signature, recommended_filename]
```

内层条款（`EncodeFileQuoteTerms`，同样 8 元数组，版本 1）：

```
[1, seed_hash, buyer_pubkey, seed_price_sat, full_block_price_sat,
 file_size, quote_expires_at_unix, supported_arbiter_pubkeys_cbor]
```

Go 结构体 `SignedFileQuote` / `FileQuoteTerms`（bitfs/messages.go）：

| 字段 | 含义 |
|---|---|
| `TermsCBOR` | 内层条款的规范 CBOR 原文，是签名的直接对象 |
| `SellerPubkey` | 卖方身份公钥，用于验证 `TermsSignature` |
| `TermsSignature` | 卖方对 `TermsCBOR` 的 DER 签名 |
| `RecommendedFilename` | 仅展示用的建议文件名，**不在签名范围内**，使用前必须过 `SanitizeRecommendedFilename` |
| `SeedHash` | 文件种子（seed）的 SHA-256，文件内容的承诺根 |
| `BuyerPubkey` | 报价专属买方——该报价只能被这个买方使用 |
| `SeedPriceSat` | 种子（首个内容单元）价格，聪 |
| `FullBlockPriceSat` | 整块价格，聪；尾块按比例上取整并给卖方 10% 计算容差（`ContentPriceSat`） |
| `FileSize` | 原始文件字节数；决定块数上限（单 payload 上限 `MaxQuoteFileSize`） |
| `QuoteExpiresAtUnix` | 报价过期时间（Unix 秒），过期即拒收 |
| `SupportedArbiterPubkeysCBOR` | 卖方认可的仲裁人公钥列表（自身也是规范 CBOR 子文档，去重校验） |

**合理性分析**

- ✅ 报价绑定唯一买方 + 过期时间 + 内容承诺（SeedHash），防止转售旧报价和无限期占单。
- ✅ `RecommendedFilename` 排除在签名外是正确的取舍：它是展示元数据而非经济事实；
  配合 sanitize 函数消除路径穿越风险。
- ✅ 仲裁人白名单放在报价里，使开池时仲裁人角色的选择有卖方背书的边界，
  防止买方挑一个与卖方有隙的仲裁人。
- ⚠️ 注意版本号体系：报价条款独立用版本 1，其余报文用主版本 4。这是有意为之
  （报价凭据独立演进），阅读代码时不要混淆。

---

### 3.2 Kind 2 · 退款预签请求（0201）— 买方 → 卖方

编码（`EncodeRefundPresignRequest`，7 元数组）：

```
[4, refund_tx, buyer_pubkey, seller_pubkey, arbiter_pubkey,
 fee_rate, buyer_refund_signature]
```

Go 结构体 `RefundPresignRequest`（pool/types.go）：

| 字段 | 含义 |
|---|---|
| `Version` | 工作流主版本，恒为 4 |
| `RefundTx` | 买方构造的预签名退款交易原始字节——**资金池身份的唯一真值来源** |
| `BuyerPubKey` / `SellerPubKey` / `ArbiterPubKey` | 三方角色公钥，顺序参与推导 2-of-3 池锁定脚本 |
| `MinerFeeRateSatPerKB` | 池内全部交易的矿工费率（sat/KB），双方后续构造交易必须一致 |
| `BuyerRefundSignature` | 买方已对该退款交易附加的 DER 签名 |

**合理性分析**

- ✅ **不携带 RefundTemplateTxID**：卖方通过 `DeriveRefundTemplateTxIDFromRequest`
  从已完成协议验证的规范未签名 `RefundTx` 派生模板交易 TxID
  （`Transaction.TxID().CloneBytes()`），
  从根上消灭了"哈希与交易不一致"的多真值问题。
- ✅ **不携带 FundingTx 原文**：资金交易 ID 和输出索引从 `RefundTx` 的 input 推导。
  买方的资金交易此时还是私有的——只有拿到卖方退款签名后才公开（0203），
  保证"钱进池子之前，退出通道已经双方签字"，这是本协议最重要的安全次序。
- ✅ 买方签名先行附上，卖方验签通过才肯签自己的那份，双方都不会先暴露裸签名。
- ✅ 费率提前锁定，避免后续任一方以费率分歧卡住状态推进。

---

### 3.3 Kind 3 · 退款预签响应（0202）— 卖方 → 买方

编码（`EncodeRefundPresignResponse`，4 元数组）：

```
[4, 13, refund_template_txid, seller_refund_signature]
```

Go 结构体 `RefundPresignResponse`：

| 字段 | 含义 |
|---|---|
| `Version` | 主版本 4 |
| （内嵌 kind `13`） | CBOR 层的消息种类标签，与传输层 Kind 3 呼应，防跨类重放 |
| `RefundTemplateTxID` | 池关联 ID。**由卖方从收到的请求规范重推导，不允许调用方自填** |
| `SellerRefundSignature` | 卖方对 `RefundTx` 的 DER 签名 |

**合理性分析**

- ✅ 关联 ID 由响应方重推导而非回显请求值，买方用它匹配自己保存的本地
  `BuyerOpeningState`（应用私有状态，非 wire 报文），天然抗篡改。
- ✅ 内嵌 kind 标签（13/14）让 CBOR 文档自带类型，即使传输层贴错 Kind 也无法跨类解码成功。
- ✅ 买方收到后的处理由应用负责：先持久化完整 `OpeningProof` 和初始退款状态，
  再继续后续步骤；SDK 不做任何保存。

---

### 3.4 Kind 4 · 资金交易交付（0203）— 买方 → 卖方

编码（`EncodeFundingTxDelivery`，4 元数组）：

```
[4, 14, refund_template_txid, funding_tx]
```

Go 结构体 `FundingTxDelivery`：

| 字段 | 含义 |
|---|---|
| `Version` | 主版本 4 |
| （内嵌 kind `14`） | CBOR 层消息种类标签 |
| `RefundTemplateTxID` | 池关联 ID，只能从买方已验证并持久化的 OpeningProof 派生 |
| `FundingTx` | 买方签名的资金交易原始字节；其第 0 个输出（`PoolOutputIndex = 0`）是池输出 |

**合理性分析**

- ✅ 这是资金交易第一次离开买方进程，时机正确：此时双方退款签名均已就位，
  即使卖方消失，买方也可在到期后单方（配合超时锁）拿回资金。
- ✅ 卖方验收时做三件事：交易 ID 匹配 pending 证据、第 0 输出金额/脚本符合推导值、
  向节点提交并确认——之后才形成完整的 `OpeningProof`（含 `FundingTx`）。
- ✅ `OpeningProof` 本身也有规范编码（9 元数组），它不单独走线，而是作为证据内嵌进 007 请求（§3.8）。

---

### 3.5 Kind 5 · 内容请求 / 最终付款授权（003）— 买方 → 卖方

外层（`EncodeSignedContentRequest`，3 元数组）：

```
[4, terms_cbor, buyer_signature]
```

内层条款（`EncodeContentRequestTerms`，无内层版本的 6 元数组）：

```
[quote_terms_hash, refund_template_txid, payment_sequence,
 seller_amount_after_sat, content_hashes_cbor, delivery_deadline_unix]
```

其中 `content_hashes_cbor` 是先对有序 hash 数组独立执行确定性 CBOR 编码、再作为 `bstr` 放入父数组的子文档（1–64 个不重复的 32 字节 hash）。

Go 结构体 `ContentRequestTerms` / `SignedContentRequest`：

| 字段 | 含义 |
|---|---|
| `TermsCBOR` | 条款规范字节，买方签名的直接对象；其 SHA-256 即 `PaymentAuthorizationHash` |
| `BuyerSignature` | 买方对精确 TermsCBOR 的 DER 签名（密钥由 OpeningProof 的 BuyerPubKey 验证） |
| `QuoteTermsHash` | 引用的 001 报价条款哈希，把本次购买锚定到具体报价；费用池不能替代报价 |
| `RefundTemplateTxID` | 所在资金池的关联 ID；Buyer/Seller/Arbiter 公钥与矿工费率全部由其 OpeningProof 唯一确定，不再重复传输 |
| `PaymentSequence` | 本次授权对应的**目标**付款序号；接收方验证它等于当前已接受序号 + 1，且不超过 0xfffffffe |
| `SellerAmountAfterSat` | 付款后卖方的**绝对累计金额**（聪）；批次价格必须等于它减去当前状态的卖方金额 |
| `ContentHashesCBOR` | 有序内容 hash 批次（1–64 项）：等于报价 SeedHash 的项即 seed，其余必须是该 seed 提交过的块；顺序是授权的一部分，重复即拒绝 |
| `DeliveryDeadlineUnix` | 交付截止时间；不得晚于报价过期时间 |

**合理性分析**

- ✅ 这份文件是整个体系的枢纽：一个付款序号授权一组内容 hash，价格逐项推导后安全累加，
  其哈希贯穿 004（交付绑定）、005（付款绑定）、007（仲裁锚定）。整个批次原子成功或原子失败。
- ✅ 不再重复携带公钥与费率：这些值已由 RefundTemplateTxID 对应且不可修改的 OpeningProof
  唯一确定。任何密码学验签都必须同时持有 OpeningProof
  （`VerifySignedContentRequestForOpening` / 完整入口 `VerifySignedContentRequest`），
  消除了“不一致时相信谁”的第二真值。
- ✅ 内容类型从证据推导：hash 等于 SeedHash 即 seed，否则必须出现在 seed 的块列表中；
  发送方没有任何声明类型的字段。
- ✅ 序号连续性（目标 = 当前 + 1）+ 绝对累计金额单调递增，使重复/乱序/回退的授权全部失效，
  天然防重放；stale、跳号、耗尽都返回稳定错误。
- ✅ 截止时间双向上限约束（未来且 ≤ 报价过期），堵住"永久有效授权"。

---

### 3.6 Kind 6 · 内容交付（004）— 卖方 → 买方

外层（`EncodeSignedContentDelivery`，固定 4 元数组；不存在单独的 DeliveryTerms 层）：

```
[4, payment_authorization_hash, seller_payment_authorization_hash_signature,
 content_payloads_cbor]
```

其中 `content_payloads_cbor` 同样是独立确定性 CBOR 编码后作为 `bstr` 嵌入的子文档（1–64 个非空 payload，单项不得超过一个 MasterSeed 块长）。

Go 结构体 `SignedContentDelivery`：

| 字段 | 含义 |
|---|---|
| `PaymentAuthorizationHash` | 所响应的 003 条款哈希（32 字节），把交付钉死到一次授权；也是应用路由 004 到本地原始 003 的索引 |
| `SellerPaymentAuthorizationHashSignature` | 卖方对**精确 32 字节哈希**的普通消息签名（SignMessage：内部再 SHA-256 一次，low-S DER）；外壳版本不入签，不签 payload、hex 或 CBOR 包装 |
| `ContentPayloadsCBOR` | 有序 payload 批次，与 003 hashes 一一对应；不进入签名，但通过 hash 链间接绑定 |

**合理性分析**

- ✅ 大 payload 不再进入签名预映像、CBOR 编码或持久化对象：卖方只对 32 字节哈希走固定消息
  签名路径，复制和存档成本与内容大小无关。
- ✅ payload 未直接入签但绑定链完整：
  `BuyerSignature → 003 TermsCBOR → ordered ContentHashesCBOR + 池 + 序号 + 金额`；
  `SHA-256(terms_cbor) = PaymentAuthorizationHash ← SellerPaymentAuthorizationHashSignature`；
  `ContentPayloadsCBOR[i] → SHA-256 → ContentHashesCBOR[i]`。
  因此接收方必须逐项验证数量、顺序、hash 与长度——任一项错误整批拒绝，绝不部分接受。
- ✅ 004 不携带池 ID 或内容 hashes：它们都能由授权哈希对应的本地保存 003 恢复；
  本地找不到 003 时只能暂存/死信或请求重发，不允许从 payload 猜测订单或费用池。
- ⚠️ 004 不自带时间：时效完全继承自所引用的 003 授权，按验收方本地 UTC 判定；
  004 不能证明买方在截止前实际收到内容，只证明卖方对该授权给出了可验证 payload。

---

### 3.7 Kind 7 · 累计付款更新（005）— 买方 → 卖方

编码（`EncodePaymentUpdate`，5 元数组）：

```
[4, refund_template_txid, payment_authorization_hash, unsigned_state_tx, buyer_signature]
```

Go 结构体 `PaymentUpdate`：

| 字段 | 含义 |
|---|---|
| `Version` | 主版本 4 |
| `RefundTemplateTxID` | 池关联 ID；不是买方签名的替代物 |
| `PaymentAuthorizationHash` | 绑定的 003 授权哈希——把付款绑到内容，而不只是绑到交易字节 |
| `UnsignedStateTxRaw` | 下一笔付款状态交易的**未签名**原始字节（三输出：买方/卖方/仲裁人分配） |
| `BuyerTransactionSignature` | 买方针对该交易 sighash 的 DER 签名，与交易分离传输 |

**合理性分析**

- ✅ "未签名交易 + 分离签名"是全程铁律：任何时刻线上都不存在"半签名交易"，
  接收方分别验证关联 ID、授权哈希、交易内容和签名后再合并，杜绝脚本拼接攻击面。
- ✅ 序号与金额不在信封里重复出现——它们编码在状态交易内部，由引擎解析并校验
  （恰好 +1、卖方累计额与 003 承诺一致、容量检查 `CheckPaymentCapacity`）。
- ✅ 卖方 `AcceptPayment` 的次序是"先验签、再自己签名、合并完整交易后返回"，
  广播与记录结果是调用方应用的职责；SDK 不提交节点，也不维护"本地领先于链"之类的运行状态。

---

### 3.8 Kind 8 · 仲裁请求（007）— 卖方 → 仲裁方

编码（`MarshalRequest`，6 元数组）：

```
[4, refund_template_txid, opening_proof_cbor, payment_authorization_cbor,
 unsigned_state_tx, seller_signature]
```

Go 结构体 `ArbitrationRequest`：

| 字段 | 含义 |
|---|---|
| `Version` | 主版本 4 |
| `RefundTemplateTxID` | 池关联 ID，置于首字段，使请求可脱离任何连接/会话独立路由 |
| `PoolOpeningProofCBOR` | 完整 002 开池证据的规范 CBOR（9 元数组：RefundTx、三方公钥、费率、双方退款签名、FundingTx） |
| `PaymentAuthorizationCBOR` | 完整的 003 已签名授权凭据 |
| `UnsignedStateTxRaw` | 卖方按授权构造的候选状态交易未签名原文 |
| `SellerTransactionSignature` | 卖方对候选交易的 DER 签名 |

**合理性分析**

- ✅ 证据自足：仲裁方仅凭这一个报文即可完成全部验证——
  ① 解码并验证开池证据（含双方退款签名、交易关系、关联 ID 重推导一致），
  从 OpeningProof 恢复 Buyer/Seller/Arbiter 公钥与矿工费率（003 不再自带这些字段）；
  ② 验证 003 的池绑定与买方对精确 TermsCBOR 的签名（`VerifySignedContentRequestForOpening`）；
  ③ 验证候选交易确实实现了授权承诺的目标序号与绝对累计金额、卖方签名有效；
  全部通过后才追加仲裁签名。仲裁人不读取 001、004、payload，也不重新计算内容定价。
- ✅ 仲裁方**只签名，不构造、不改写、不广播**（`Workflow` 的硬性约束）：
  候选交易由卖方提供且被逐项验证，仲裁人不会成为交易构造方，也就不承担内容定价或交易合法性之外的责任。
- ✅ `BuildArbitrationRequest(PaymentUpdate)` 被显式禁用（返回错误），强制仲裁必须从
  003 授权出发而不是从买方付款包装出发——保证仲裁语义是"执行买方授权"而非"追认买方付款"。
- ✅ 卖方签名分离传输，仲裁人验签后原样保留，最终由卖方合并双签名提交节点。

---

### 3.9 Kind 9 · 仲裁响应（007）— 仲裁方 → 卖方

编码（`MarshalResponse`，5 元数组）：

```
[4, refund_template_txid, payment_authorization_hash, unsigned_state_tx_hash, arbiter_signature]
```

Go 结构体 `ArbitrationResponse`：

| 字段 | 含义 |
|---|---|
| `Version` | 主版本 4 |
| `RefundTemplateTxID` | 经仲裁方验证过的池关联 ID 回执 |
| `PaymentAuthorizationHash` | 仲裁方实际签过的授权哈希，定义为 SHA-256(003 TermsCBOR)，与 004/005 携带的授权哈希完全一致；完整 003 外壳的哈希不是授权哈希 |
| `UnsignedStateTxHash` | 仲裁方实际签过的候选交易字节哈希 |
| `ArbiterTransactionSignature` | 仲裁人对候选交易 sighash 的 DER 签名 |

**合理性分析**

- ✅ 两个哈希回执是关键：卖方无需信任"仲裁人签的是哪份东西"——
  自己重算哈希比对（`CompleteArbitratedPayment` 用同一算法
  `SHA-256(003 TermsCBOR)` 复核授权哈希、用候选交易字节复核交易哈希，
  并把响应 `RefundTemplateTxID` 与原请求逐字节绑定）即可确认签名对象与本地候选一字不差，
  然后才合并签名返回；广播仍由应用执行。哈希回执把信任问题降为字节比较问题。
- ✅ 授权哈希全链唯一：同一张 003 的 PaymentAuthorizationHash 在 004、005 与 007 中
  必须逐字节相等（集成测试覆盖），杜绝"同一授权在不同报文中出现不同身份"。
- ✅ 拒绝语义 = 返回错误/无响应，不设"拒绝"标志位，避免半吊子的否定凭据流通。
- ⚠️ 响应不含候选交易原文：若卖方丢失了自己的候选交易，仅有响应无法重建。
  但候选交易本就由卖方构造并可从持久化状态重推导，此取舍合理。

---

## 4. 贯穿全局的三条主线

### 4.1 关联 ID：RefundTemplateTxID

```
规范未签名 RefundTx（预签退款交易字节）
   └── Transaction.TxID().CloneBytes() ──► RefundTemplateTxID = 资金池统一关联 ID
                       ├── 0202/0203/005/007 报文的路由键
                       ├── 双方本地开池证据记录（应用数据库）的主键
                       ├── 买方本地 BuyerOpeningState（应用私有状态）的键
                       └── 付款状态链（PaymentState.RefundTemplateTxID）的归属标识
```

规则：凡能从 `RefundTx` 推导的地方一律不重复传；凡携带它的报文都禁止全零值。

### 4.2 授权链：一份 003 贯穿始终

```
001 报价 ──(QuoteTermsHash)──► 003 授权 ──(SHA-256 = PaymentAuthorizationHash)
                                   │
                     ┌─────────────┼─────────────┐
                     ▼             ▼             ▼
                004 交付      005 付款更新     007 仲裁请求
             （卖方签什么）  （买方为什么付）  （仲裁裁什么）
```

### 4.3 签名矩阵

| 报文/对象 | 签名人 | 覆盖内容 |
|---|---|---|
| 001 条款 | 卖方 | TermsCBOR |
| 退款交易 | 买方 + 卖方 | 退款交易 sighash（各出一份，合入解锁脚本） |
| 003 条款 | 买方 | TermsCBOR |
| 004 授权哈希 | 卖方 | 精确 32 字节 PaymentAuthorizationHash（裸消息签名，不含 payload） |
| 005 状态交易 | 买方（线上）→ 卖方合并 | 交易 sighash |
| 007 候选交易 | 卖方（线上）→ 仲裁方追加 | 同一交易 sighash |

---

## 5. 006 关闭为何没有报文

无条件关闭（006）复用既有数据结构，在 API 层传递而非定义新的线上类型：

1. 买方 `BuildImmediateClose` → 产出 `*pool.UnsignedPayment` + 买方签名
   （`PaymentSequence = ^uint32(0)` 表示终态）。
2. 卖方 `SignImmediateClose` → 补卖方签名，返回 `*pool.SignedPayment`。
3. 买方 `CompleteImmediateClose` → 复核完整终态交易并返回；广播与落库由应用执行。

理由：关闭交易与 005 状态交易同构，只是序号为终态哨兵；引入新报文只会增加一套
编解码与校验面，无安全增益。到期退款路径同理——直接组装 OpeningProof 中已存的
双方退款签名广播，无需新报文。

---

## 6. 合理性审查汇总

| # | 报文 | 结论 | 备注 |
|---:|---|---|---|
| 1 | 001 报价 | ✅ 合理 | 文件名排除在签名外且有消毒；仲裁人白名单前置 |
| 2 | 0201 预签请求 | ✅ 合理 | 无冗余哈希字段；FundingTx 延迟公开是核心安全次序 |
| 3 | 0202 预签响应 | ✅ 合理 | 关联 ID 重推导 + 内嵌 kind + 幂等重放 |
| 4 | 0203 资金交付 | ✅ 合理 | 双方退款签名齐备后才公开资金交易 |
| 5 | 003 内容请求 | ✅ 合理 | 单一目标序号 + 绝对累计金额；身份/费率由 OpeningProof 唯一确定；一个序号授权一批内容 |
| 6 | 004 内容交付 | ✅ 合理 | 裸授权哈希签名 + payload 间接绑定；批次原子验收（注意必须逐项校验 hash） |
| 7 | 005 付款更新 | ✅ 合理 | 未签名交易 + 分离签名；授权哈希绑定内容 |
| 8 | 007 仲裁请求 | ✅ 合理 | 证据自足；仲裁人只签名不构造；从授权而非付款构建（强制） |
| 9 | 007 仲裁响应 | ✅ 合理 | 哈希回执将信任降为字节比较；拒绝即无响应 |

整体评价：报文集合没有冗余类型，每个字段要么被签名覆盖、要么可从签名材料推导、
要么明确标注为非经济事实（如 RecommendedFilename）。"单一真值 + 分离签名 +
严格规范编码 + 幂等重放"四个纪律在全部九类报文中贯彻一致。

---

## 附：代码索引

| 内容 | 位置 |
|---|---|
| Kind 定义与 Marshal/Unmarshal 分发 | `wire/wire.go:26`、`wire/wire.go:67` |
| 报价结构与编码 | `bitfs/messages.go`、`bitfs/quote.go:71` |
| 内容请求/交付结构与编码 | `bitfs/content.go:88`、`bitfs/content.go:252` |
| 池报文结构体 | `pool/types.go:85`–`pool/types.go:146` |
| 池报文 CBOR 编解码 | `pool/cbor.go` |
| 开池证据编码（内嵌 007） | `pool/cbor.go:255` |
| 仲裁请求/响应与验证工作流 | `arbitration/workflow.go:50`–`arbitration/workflow.go:151` |
| 买方工作流（001–006） | `buyer/workflow.go` |
| 卖方工作流（001–007） | `seller/workflow.go` |
| CDDL 规范 | `spec/v4/{bitfs,content,pool,payment,arbitration}.cddl` |
