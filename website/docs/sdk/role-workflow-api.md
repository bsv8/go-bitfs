---
id: role-workflow-api
title: 03 · Role workflow API
---

# 03 · Role workflow API

Every workflow holds only the constrained signer fixed at construction.
Methods never load or save state,
never send messages, never broadcast transactions, and never read a node or a
clock; each time- or height-sensitive call receives one explicit
`protocol.Facts{Now, BlockHeight}` value and validates protocol rules against it.
Each method lists its wire input, local input, wire output, local output, and
side-effect guarantee. The application persists every returned checkpoint (and
the exact `Outbound.Bytes()` of every Artifact) before sending, serializes
concurrent work per pool, sends wire messages, and broadcasts raw transactions
through its own node adapter.

Construction is uniform across roles — keys enter through the single signer
port:

```go
signer, err := protocol.NewPrivateKeySigner(key) // key 为 *ec.PrivateKey（官方 BSV Go SDK）
buyerWf, err := buyer.NewWorkflow(signer)
sellerWf, err := seller.NewWorkflow(signer)
arbiterWf, err := arbiter.NewWorkflow(signer)    // 每个角色用自己的 Signer，不得混用
```

Recommended application ordering for every step:

```
load（按 RefundTemplateTxID / 授权 ID 加载 checkpoint）
→ 角色 API compute/verify（显式传入全部前序证据与 Facts）
→ persist checkpoint/outbox（先保存 Checkpoint 与 Outbound.Bytes()）
→ send/broadcast → record outcome
```

## Buyer API

```go
// package buyer

func NewWorkflow(signer protocol.Signer) (*Workflow, error)

// 每个角色 workflow 都暴露构造时固定的压缩公钥（三角色同签名）：
func (w *Workflow) PublicKey() []byte

// AcceptQuote 严格解析 exact Kind 1 bytes，验签并以 facts.Now 判过期，
// 返回不可变 VerifiedQuote。应用决定保存位置；SDK 不落任何存储。
func (w *Workflow) AcceptQuote(facts protocol.Facts, rawKind1 []byte) (*content.VerifiedQuote, error)
    // Verified* 值只能由验证入口获得：content.VerifyQuoteForBuyer /
    // pool.VerifyOpeningProof / pool.VerifyPaymentState / pool.VerifySignedTransaction。
    // 不存在公开的无验证构造器；伪造 DTO 无法被包装成 Verified。

// PreparePoolOpening 构造并签署 Kind 2 预签请求：返回待发送 Artifact 与必须
// 先持久化的 OpeningCheckpoint。资金交易原文只存在于 checkpoint。
func (w *Workflow) PreparePoolOpening(ctx context.Context, command PrepareOpeningCommand) (*PreparePoolOpeningResult, error)

type PrepareOpeningCommand struct {
    Quote                           *content.VerifiedQuote // AcceptQuote 的返回值
    FundingTransactionRaw           []byte                 // 输出 0 必须是池输出
    ExpiryLockTime                  uint32                 // 退款到期锁定（timestamp 或高度）
    MinerFeeRateSatoshisPerKilobyte uint64
    SellerPublicKey                 protocol.PublicKey
    ArbiterPublicKey                protocol.PublicKey
}

type PreparePoolOpeningResult struct {
    Outbound   wire.Artifact       // 待发送 exact Kind 2；先持久化 Checkpoint 再发送
    Checkpoint *OpeningCheckpoint  // 含私有资金交易原文
}

// CompletePoolOpening 用保存的 OpeningCheckpoint 验收 exact Kind 3：重派生池
// 关联 ID 并拒绝任何错配，验卖方预签，产出 verified opening 与初始池 checkpoint。
func (w *Workflow) CompletePoolOpening(checkpoint *OpeningCheckpoint, rawKind3 []byte) (*CompleteOpeningResult, error)

type CompleteOpeningResult struct {
    Opening     *pool.VerifiedOpening // 完整已验证开池证明
    InitialPool *PoolCheckpoint       // 初始池 checkpoint（sequence=2、卖方/仲裁金额为零）
}

// PrepareFundingDelivery 把 verified opening 携带的资金交易打包成 Kind 4
// Artifact；不广播资金交易——广播边界属于应用。
func (w *Workflow) PrepareFundingDelivery(poolCheckpoint *PoolCheckpoint) (wire.Artifact, error)

// RequestContent 验证报价/池/批次上下文/聚合价格/余额后签署 003。
func (w *Workflow) RequestContent(ctx context.Context, facts protocol.Facts, command RequestContentCommand) (*RequestContentResult, error)

type RequestContentCommand struct {
    Quote            *content.VerifiedQuote
    Pool             *PoolCheckpoint      // opening + previous payment state
    ContentHashes    [][]byte             // 有序不重复批次（1..64）；等于 SeedHash 即购 seed
    DeliveryDeadline content.UnixSeconds  // UTC Unix 秒；晚于 facts.Now 且不超过报价有效期
    Seed             []byte               // 批次包含任何块时必须提供
}

type RequestContentResult struct {
    Outbound        wire.Artifact              // 待发送 exact Kind 5
    AuthorizationID protocol.PaymentAuthorizationID // 授权 typed ID（内容寻址键）
    Checkpoint      *AuthorizationCheckpoint   // 与 Outbound 一同持久化后再发送
}

// VerifyDeliveryAndPreparePayment 验收 exact Kind 6 并产生整批唯一的 Kind 7
// 签名凭证。方法名显式暴露"会产生买方交易签名"；先保存 payloads 与 Result
// 再发送 Outbound。
func (w *Workflow) VerifyDeliveryAndPreparePayment(ctx context.Context, facts protocol.Facts, command VerifyDeliveryCommand) (*PaymentPreparationResult, error)

type VerifyDeliveryCommand struct {
    Quote       *content.VerifiedQuote
    Pool        *PoolCheckpoint
    Request     *AuthorizationCheckpoint // 本批次持久化的授权 checkpoint
    DeliveryRaw []byte                   // 对端发来的 exact Kind 6 bytes
    Seed        []byte
}

type PaymentPreparationResult struct {
    Payloads      [][]byte             // 已验证 payload 批次（落盘由应用负责）
    Outbound      wire.Artifact        // 待发送 exact Kind 7 最小付款凭证
    NextCandidate *pool.UnsignedPayment // 确定性重建的目标未签名状态（本地审计用）
}

// PrepareClose 从调用方选定的基准状态与目标金额构造未签名关闭 candidate 和
// 买方 detached 签名。SDK 不声称 base 是业务最新，也不判断目标金额是否符合
// 订单或账本。两者都须先持久化再发送给卖方。
func (w *Workflow) PrepareClose(ctx context.Context, facts protocol.Facts, command PrepareCloseCommand) (*ClosePreparationResult, error)

type PrepareCloseCommand struct {
    Pool                       *PoolCheckpoint
    Base                       *pool.PaymentState // 调用方选定的基准状态
    TargetSellerAmountSatoshis protocol.Satoshis
}

type ClosePreparationResult struct {
    Unsigned       *pool.UnsignedPayment // sequence=4294967295 的未签名关闭 candidate
    BuyerSignature []byte                // 买方 detached 交易签名
}

// VerifyCompletedClose 验证卖方完整关闭交易在给定 opening 下密码学、结构与
// 交易关系全部正确；不声称已广播或已确认。
func (w *Workflow) VerifyCompletedClose(command VerifyCloseCommand) (*pool.VerifiedSignedTransaction, error)

type VerifyCloseCommand struct {
    Pool  *PoolCheckpoint
    Close *pool.SignedPayment // 卖方合并后的完整关闭交易
}

// BuildMaturedRefund 在显式事实判定退款到期后合并双方退款签名，返回可广播的
// verified refund transaction；是否广播由应用决定。未到期时返回
// CodeNotMatured 分类错误。
func (w *Workflow) BuildMaturedRefund(facts protocol.Facts, poolCheckpoint *PoolCheckpoint) (*pool.VerifiedSignedTransaction, error)

// RequestArbitratedContent 为一条托管记录构造 exact Kind 10 Artifact：默认入口
// 由 SDK 生成安全随机 nonce；网络超时重试必须原样重放已持久化的 Artifact，
// 绝不能重新调用本方法生成新 nonce。
func (w *Workflow) RequestArbitratedContent(ctx context.Context, command ArbitrationRetrievalCommand) (wire.Artifact, error)

type ArbitrationRetrievalCommand struct {
    Pool          *PoolCheckpoint          // 当前池 checkpoint
    Authorization *AuthorizationCheckpoint // exact 已签 003 的 checkpoint
}

// VerifyArbitratedContent 时间无关地验收 exact Kind 10/11：available 分支额外
// 复核 payload 归属与价格；unavailable 分支作为已验签协议结果返回。
func (w *Workflow) VerifyArbitratedContent(ctx context.Context, command ArbitratedContentCommand) (*ArbitratedContentResult, error)

type ArbitratedContentCommand struct {
    Quote                *content.VerifiedQuote
    Pool                 *PoolCheckpoint
    Request              *AuthorizationCheckpoint
    RetrievalRequestRaw  []byte // 本地保存的 exact Kind 10（原样重放）
    RetrievalResponseRaw []byte // 对端返回的 exact Kind 11
    Seed                 []byte
}

type ArbitratedContentResult struct {
    ContentRetrievalRequestID protocol.ContentRetrievalRequestID
    ArbitrationClaimID        protocol.ArbitrationClaimID
    Available                 bool // false 表示 valid unavailable：typed 结果，不是 error
    UnavailableReason         arbitration.ContentRetrievalUnavailableReason
    Payloads                  [][]byte // 仅 Available=true 时非空；两种分支都不产生付款凭证
}
```

Opaque buyer checkpoints expose deep-copy getters only:

```go
// OpeningCheckpoint：RefundTemplateTxID() / Request() / FundingTransactionRaw()
// PoolCheckpoint：Opening() / Payment() / VerifiedPayment() / VerifiedOpening() /
//                 RefundTemplateTxID()
// AuthorizationCheckpoint：AuthorizationID() / Request()

// Restore 入口从 exact persisted evidence 全量重验恢复（崩溃恢复用）：
func RestoreOpeningCheckpoint(rawKind2 []byte, fundingTransactionRaw []byte) (*OpeningCheckpoint, error)
func RestorePoolCheckpoint(openingProofCBOR []byte, paymentRawTx []byte) (*PoolCheckpoint, error)

// 三份 exact evidence（Kind1 + Kind5 + opening proof）全链重验后恢复授权。
func RestoreAuthorizationCheckpoint(rawKind1, rawKind5, openingProofCBOR []byte) (*AuthorizationCheckpoint, error)

```

## Seller API

The seller workflow has no lease or pending-request store: `DeliverContent`
returns a lock-free `DeliveryCheckpoint` recording exactly the protocol context
needed later by `CompletePayment`, and the application saves it and passes it
back explicitly.

```go
// package seller

func NewWorkflow(signer protocol.Signer) (*Workflow, error)

// CreateQuote 以单一 QuoteDraft 签署确定性 Kind 1 条款：先 sanitize 文件名再
// 编码与签名，返回待发送 Artifact 与最终规范化 terms（展示实际签署值）。
func (w *Workflow) CreateQuote(ctx context.Context, facts protocol.Facts, draft QuoteDraft) (*QuoteResult, error)

type QuoteDraft struct {
    SeedHash                   []byte             // 内容仓库种子摘要（SHA-256）
    BuyerPublicKey             protocol.PublicKey // 唯一被授权买方
    SeedPriceSatoshis          protocol.Satoshis  // 整个 MasterSeed 的绝对单价
    FullBlockPriceSatoshis     uint64             // 一个完整块（256 KiB）的单价
    FileSizeBytes              uint64             // 块数由它派生
    QuoteExpiresAtUnixSeconds  int64              // 必须晚于 facts.Now
    SupportedArbiterPublicKeys [][]byte           // 可为空但不得重复
    RecommendedFilename        string             // 唯一文件名来源；sanitize 后进入签名条款
}

type QuoteResult struct {
    Outbound wire.Artifact            // 待发送 exact Kind 1
    Terms    *content.FileQuoteTerms  // 最终规范化并已签署的条款快照
}

// PreparePoolOpening 验证 exact Kind 2 并计算卖方退款预签：返回待发送 Kind 3
// Artifact 与必须先持久化的 OpeningCheckpoint。
func (w *Workflow) PreparePoolOpening(ctx context.Context, rawKind2 []byte) (*PreparePoolOpeningResult, error)

type PreparePoolOpeningResult struct {
    Outbound   wire.Artifact       // 待发送 exact Kind 3
    Checkpoint *OpeningCheckpoint  // 预签证据；VerifyFundingDelivery 需要它
}

// VerifyFundingDelivery 用保存的预签 checkpoint 验收 exact Kind 4：完成开池
// 证明并解析初始退款状态。FundingTransactionRaw 由应用自行广播；
// InitialPool 必须在广播决策前持久化。
func (w *Workflow) VerifyFundingDelivery(checkpoint *OpeningCheckpoint, rawKind4 []byte) (*FundingVerificationResult, error)

type FundingVerificationResult struct {
    Opening               *pool.VerifiedOpening
    InitialPool           *PoolCheckpoint
    FundingTransactionRaw []byte // 已验证资金交易字节的原样副本，供应用广播
}

// DeliverContent 验证买方 003 全链证据后构造并签署 Kind 6：返回待发送
// Artifact 与必须先持久化的 DeliveryCheckpoint（先保存后发送）。
func (w *Workflow) DeliverContent(ctx context.Context, facts protocol.Facts, command DeliveryCommand) (*DeliveryResult, error)

type DeliveryCommand struct {
    Quote           *content.SignedFileQuote // 本池对应的已签报价
    Pool            *PoolCheckpoint
    RequestRaw      []byte                   // 买方发来的 exact Kind 5 bytes
    ContentPayloads [][]byte                 // 顺序与授权哈希一一对应
    Seed            []byte
}

type DeliveryResult struct {
    Outbound   wire.Artifact        // 待发送 exact Kind 6
    Checkpoint *DeliveryCheckpoint  // 记录验收买方付款凭证所需的全部协议上下文
}

// CompletePayment 验证买方最小 Kind 7 凭证、补签并合并完整交易：返回完整交易
// （仅供应用决定是否广播）与 next pool checkpoint。
func (w *Workflow) CompletePayment(ctx context.Context, facts protocol.Facts, command PaymentCommand) (*CompletePaymentResult, error)

type PaymentCommand struct {
    Pool       *PoolCheckpoint
    Request    *content.SignedContentRequest // 按 005 携带的授权 ID 取回的原始 003
    UpdateRaw  []byte                        // 对端发来的 exact Kind 7 bytes
    Checkpoint *DeliveryCheckpoint           // 生成本批次 004 时保存者
}

type CompletePaymentResult struct {
    Transaction *pool.VerifiedSignedTransaction // 完整签名付款交易；广播边界属于应用
    NextPool    *PoolCheckpoint                 // 合并后的本地 verified 状态
}

// CompleteClose 校验买方关闭 candidate 结构与角色签名后补签并合并完整交易。
// 它不读取任何卖方数据库金额，也不判断 candidate 是否匹配业务目标。
func (w *Workflow) CompleteClose(ctx context.Context, facts protocol.Facts, command CloseCommand) (*pool.VerifiedSignedTransaction, error)

type CloseCommand struct {
    Pool           *PoolCheckpoint
    Unsigned       *pool.UnsignedPayment // 买方 prepared 的未签名关闭 candidate
    BuyerSignature []byte
}

// PrepareArbitration 验证本地开池、买方授权与本方已发交付后，签署紧凑 Claim
// 证据并返回 exact Kind 8 Artifact。它不构造也不预测仲裁方响应。
func (w *Workflow) PrepareArbitration(ctx context.Context, facts protocol.Facts, command ArbitrationCommand) (wire.Artifact, error)

type ArbitrationCommand struct {
    Pool        *PoolCheckpoint
    Request     *content.SignedContentRequest // 被托管批次的 exact 已签 003
    DeliveryRaw []byte                        // 本方发出的 exact Kind 6 bytes
}

// CompleteArbitratedPayment 从 exact Kind 8/9 完整验证托管收款路径：独立重建
// paid candidate、验证回执消息签名与仲裁交易签名，然后补签卖方交易签名并合并
// 完整交易。不广播。
func (w *Workflow) CompleteArbitratedPayment(ctx context.Context, facts protocol.Facts, command ArbitratedPaymentCommand) (*pool.VerifiedSignedTransaction, error)

type ArbitratedPaymentCommand struct {
    RequestRaw           []byte // exact Kind 8 bytes
    ResponseRaw          []byte // exact Kind 9 bytes
    DeliveryPayloadsCBOR []byte // 本方保存的 exact payload bundle（可选；提供时逐字节比对）
}
```

Seller checkpoints: `OpeningCheckpoint.Opening()` returns the presign-form
proof; `PoolCheckpoint` mirrors the buyer shape (`Opening()` / `Payment()` /
`VerifiedOpening()` / `RefundTemplateTxID()`); `DeliveryCheckpoint` exposes
`RefundTemplateTxID()` / `AuthorizationID()` / `PaymentSequence()` /
`SellerAmountAfterSatoshis()`.

## Arbiter API

The arbiter receives complete evidence instead of querying buyer or seller state. It does not decide whether content was delivered or recalculate quote amounts. The arbitration fee is an application decision: price it from exactly `len(ContentPayloadsCBOR)` with your own integer policy, and hand the explicit amount to the SDK.

// Seller 侧对称恢复入口（从 exact evidence 全量重验）：
func RestoreOpeningCheckpoint(rawKind2 []byte, rawKind3 []byte) (*OpeningCheckpoint, error)
func RestorePoolCheckpoint(openingProofCBOR []byte, paymentRawTx []byte) (*PoolCheckpoint, error)

// RestoreDeliveryCheckpoint 全量重验四份 exact evidence：Kind1+Opening 重建
// 角色绑定；003 走全链证据验证；004 绑定授权 ID 并证明本方签署过该交付。
func RestoreDeliveryCheckpoint(rawKind1, openingProofCBOR, rawKind5, rawKind6 []byte) (*DeliveryCheckpoint, error)

// 构造时固定的压缩公钥。
func (w *Workflow) PublicKey() []byte

```go
// package arbiter

func NewWorkflow(signer protocol.Signer) (*Workflow, error)

// PrepareArbitration 对 exact Kind 8 托管请求做完整证据验证但绝不签名：
// Claim 结构、买方授权签名、卖方 Claim 签名、逐 payload 哈希、按显式正仲裁费
// 独立重建 candidate、Claim 归属校验、交付截止未过（facts.Now）、退款模板尚未
// 到期（facts.BlockHeight）。fee 为 0 时按 invalid_evidence 分类拒绝。
func (w *Workflow) PrepareArbitration(facts protocol.Facts, rawKind8 []byte, fee protocol.Satoshis) (*arbitration.PreparedArbitration, error)

// PreparedArbitration 深复制 getter：
// Request() / RequestCBOR() / Claim() / RefundTemplateTxID() /
// ArbitrationClaimID() / PaymentAuthorizationID() / FeeSatoshis() /
// ContentPayloadsCBOR() / ContentPayloads() / DeadlineUnixSeconds() /
// ArbiterPublicKey()

// SignPreparedArbitration 是先持久化后的签名步骤：从冻结的 exact Kind 8 字节
// 独立重建交易与 digest，重新比较 Claim ID、费用、角色、deadline（本次显式
// Facts.Now）与 candidate，然后按固定顺序签名——先仲裁交易签名，再编码回执，
// 最后生成并自验统一回执消息签名。绝不信任缓存的 mutable candidate。
func (w *Workflow) SignPreparedArbitration(ctx context.Context, facts protocol.Facts, prepared *arbitration.PreparedArbitration) (wire.Artifact, error)

// AuthenticateRetrieval 仅完成 Buyer 鉴权，用于 not_ready / gone 分支：
// 时间无关，不需要 Kind 9 存在。
func (w *Workflow) AuthenticateRetrieval(rawKind10 []byte, storedKind8 []byte) error

// VerifyRetrievableCustody 对完整托管证据（exact Kind 8 + exact Kind 9）做
// 时间无关全量验证，再鉴权 exact Kind 10，最后返回 verified custody/payload。
// 过期的 deadline 或已到期的退款锁定不会拒绝仍在保留窗口内的已签托管证据。
func (w *Workflow) VerifyRetrievableCustody(rawKind10 []byte, storedKind8 []byte, storedKind9 []byte) (*arbitration.VerifiedCustodiedContent, error)

// BuildUnavailableRetrieval 构造并签署 valid Kind 11 unavailable Artifact：
// 只携带结构合法的 request ID 与诚实 reason。
func (w *Workflow) BuildUnavailableRetrieval(ctx context.Context, requestID protocol.ContentRetrievalRequestID, reason arbitration.ContentRetrievalUnavailableReason) (wire.Artifact, error)

// BuildAvailableRetrieval 构造并签署 valid Kind 11 available Artifact，直接
// 附带经 content_payloads_id 绑定的 verified exact payloads。available 分支
// 不产生也不携带任何付款凭证。
func (w *Workflow) BuildAvailableRetrieval(ctx context.Context, requestID protocol.ContentRetrievalRequestID, verifiedCustody *arbitration.VerifiedCustodiedContent) (wire.Artifact, error)
```

## Error categories

Every method returns `*protocol.Error`; applications branch only on the stable
classification via `protocol.IsCode(err, code)` / `protocol.CodeOf(err)` — never on error text:

| Code | 含义 | 典型触发 |
|---|---|---|
| `CodeMalformedWire` | 报文结构、数组形状或字段宽度畸形 | 解析 exact bytes 失败 |
| `CodeNonCanonical` | 结构合法但编码不是 deterministic CBOR | 对端重编码了报文 |
| `CodeUnsupportedVersion` | wire version 不是 1 | 版本错配 |
| `CodeUnsupportedKind` | Kind 不在 1..11 或与路由声明不一致 | 路由与自描述 Kind 冲突 |
| `CodeInvalidSignature` | 消息或交易签名验证失败 | 对端密钥不符或签名被篡改 |
| `CodeInvalidEvidence` | 哈希不匹配、池绑定失败、金额守恒破坏等 | 证据链断裂 |
| `CodeUnauthorized` | 角色公钥与操作者身份不符 | 报价/开池指向其他角色 |
| `CodeExpired` | 报价过期、交付截止已过或退款锁定已到期 | Facts.Now 判定过期 |
| `CodeNotMatured` | 退款锁定尚未到期（正向操作被拒） | 提前调用 BuildMaturedRefund |
| `CodeStateConflict` | 序号陈旧、checkpoint 与证据错配 | 本地状态落后或错配 |
| `CodeInsufficientBalance` | 付款超出资金池余额或容量 | 批次价格超余额 |
| `CodeCanceled` | 调用方 context 取消或超时 | 调用方中断 |
| `CodeSignerUnavailable` | 密钥托管方暂时无法完成签名 | HSM/KMS 故障；对同一 prepared 输入重试 |

## Complete business flow

### 1. Create one capability set for each role

```go
signerBuyer, _ := protocol.NewPrivateKeySigner(buyerKey)
signerSeller, _ := protocol.NewPrivateKeySigner(sellerKey)
signerArbiter, _ := protocol.NewPrivateKeySigner(arbiterKey)
buyerWorkflow, _ := buyer.NewWorkflow(signerBuyer)
sellerWorkflow, _ := seller.NewWorkflow(signerSeller)
arbiterWorkflow, _ := arbiter.NewWorkflow(signerArbiter)
facts := protocol.Facts{Now: observedUTC, BlockHeight: height}
```

### 2. The seller creates a quote and the buyer accepts it

```go
qr, err := sellerWorkflow.CreateQuote(ctx, facts, seller.QuoteDraft{ /* ... */ })
journal.SaveOutbox("kind1", qr.Outbound.Bytes()) // 先持久化 exact bytes
sendToBuyer(qr.Outbound.Bytes())

vq, err := buyerWorkflow.AcceptQuote(ctx, facts, receivedKind1Raw)
```

### 3. The buyer and seller open the payment pool

```go
// 0201: compute request + private state; SAVE Checkpoint BEFORE sending Outbound.
prepared, err := buyerWorkflow.PreparePoolOpening(ctx, buyer.PrepareOpeningCommand{ /* ... */ })
journal.SaveBuyerOpening(prepared.Outbound.Bytes(), prepared.Checkpoint)
sendToSeller(prepared.Outbound.Bytes())

// 0202: verify and presign; SAVE Checkpoint BEFORE sending Outbound.
presign, err := sellerWorkflow.PreparePoolOpening(ctx, receivedKind2Raw)
journal.SaveSellerPresign(presign.Checkpoint)
sendToBuyer(presign.Outbound.Bytes())

// 0203: restore from exact persisted evidence, then accept the response.
restored, err := buyer.RestoreOpeningCheckpoint(savedKind2Raw, savedFundingRaw)
completed, err := buyerWorkflow.CompletePoolOpening(restored, receivedKind3Raw)
buyerPool := completed.InitialPool

// 0204: package the funding transaction; 0205: verify against the saved presign.
deliveryArtifact, _ := buyerWorkflow.PrepareFundingDelivery(ctx, buyerPool)
sendToSeller(deliveryArtifact.Bytes())
opened, err := sellerWorkflow.VerifyFundingDelivery(ctx, savedPresignCheckpoint, receivedKind4Raw)
broadcast(opened.FundingTransactionRaw) // your node adapter declares acceptance
```

### 4. The buyer requests content and the seller delivers it

```go
rc, err := buyerWorkflow.RequestContent(ctx, facts, buyer.RequestContentCommand{ /* ... */ })
journal.SaveAuthorization(rc.AuthorizationID, rc.Checkpoint) // save BEFORE sending
sendToSeller(rc.Outbound.Bytes())

dr, err := sellerWorkflow.DeliverContent(ctx, facts, seller.DeliveryCommand{ /* ... */ })
journal.SaveDeliveryCheckpoint(dr.Checkpoint) // save BEFORE sending
sendToBuyer(dr.Outbound.Bytes())
```

### 5. The buyer verifies delivery and the seller completes payment

```go
pp, err := buyerWorkflow.VerifyDeliveryAndPreparePayment(ctx, facts, buyer.VerifyDeliveryCommand{
    Quote: vq, Pool: buyerPool, Request: savedAuthCheckpoint,
    DeliveryRaw: receivedKind6Raw, Seed: seedBytes,
})
for _, payload := range pp.Payloads { save(payload) } // app persistence first
sendToSeller(pp.Outbound.Bytes())                    // then send the Kind 7 credential

authCP := journal.LoadAuthorizationByID(ppAuthID())  // app lookup by authorization ID
deliveryCP := journal.LoadDeliveryCheckpointByAuth(ppAuthID())
completedPay, err := sellerWorkflow.CompletePayment(ctx, facts, seller.PaymentCommand{
    Pool: sellerPool, Request: authCP.Request(), UpdateRaw: receivedKind7Raw,
    Checkpoint: deliveryCP,
})
broadcast(completedPay.Transaction.RawTx())
sellerPool = completedPay.NextPool
```

### 6. Custody branch for a payment exception

```go
kind8, err := sellerWorkflow.PrepareArbitration(ctx, facts, seller.ArbitrationCommand{
    Pool: sellerPool, Request: savedAuthCheckpoint.Request(), DeliveryRaw: sentKind6Raw,
})
rawKind8 := kind8.Bytes() // persist BEFORE sending

prepared, err := arbiterWorkflow.PrepareArbitration(ctx, facts, rawKind8, explicitFee)
if err := journal.PersistCustody(prepared); err != nil { /* abort signing */ }
kind9, err := arbiterWorkflow.SignPreparedArbitration(ctx, facts, prepared)
journal.AppendResponse(rawKind8, kind9.Bytes()) // append-only

signed, err := sellerWorkflow.CompleteArbitratedPayment(ctx, facts, seller.ArbitratedPaymentCommand{
    RequestRaw: rawKind8, ResponseRaw: kind9.Bytes(),
})
broadcast(signed.RawTx())
```

### 7. Two other endings: negotiated close and expiry refund

```go
closePrep, _ := buyerWorkflow.PrepareClose(ctx, facts, buyer.PrepareCloseCommand{
    Pool: buyerPool, Base: base, TargetSellerAmountSatoshis: target,
})
closed, _ := sellerWorkflow.CompleteClose(ctx, facts, seller.CloseCommand{
    Pool: sellerPool, Unsigned: closePrep.Unsigned, BuyerSignature: closePrep.BuyerSignature,
})
final, _ := buyerWorkflow.VerifyCompletedClose(ctx, buyer.VerifyCloseCommand{
    Pool: buyerPool, Close: closed,
})
broadcast(final.RawTx())

refund, _ := buyerWorkflow.BuildMaturedRefund(ctx, facts, buyerPool)
broadcast(refund.RawTx())
```

### 8. Buyer retrieval of arbitrated custody content (008)

When the seller and buyer cannot connect directly but both reach the arbiter:

```go
k10, err := buyerWorkflow.RequestArbitratedContent(ctx, buyer.ArbitrationRetrievalCommand{
    Pool: buyerPool, Authorization: savedAuthCheckpoint,
})
rawKind10 := k10.Bytes()
journal.SaveOutbox("kind10", rawKind10) // persist BEFORE sending; timeouts replay these exact bytes
sendToArbiter(rawKind10)

// Arbiter application: strict decode -> replay of the first persisted answer ->
// authenticate -> sign the matching Kind 11 branch (binding verified payloads
// through content_payloads_id on the available branch).
custody, err := arbiterWorkflow.VerifyRetrievableCustody(rawKind10, storedKind8, storedKind9)
answer, err := arbiterWorkflow.BuildAvailableRetrieval(ctx, requestID, custody)
// or: answer, err = arbiterWorkflow.BuildUnavailableRetrieval(ctx, requestID, reason)
sendToBuyer(answer.Bytes())

// Buyer: full time-independent acceptance.
outcome, err := buyerWorkflow.VerifyArbitratedContent(ctx, buyer.ArbitratedContentCommand{
    Quote: vq, Pool: buyerPool, Request: savedAuthCheckpoint,
    RetrievalRequestRaw: rawKind10, RetrievalResponseRaw: receivedKind11Raw,
    Seed: seedBytes,
})
if outcome.Available {
    for _, payload := range outcome.Payloads { save(payload) } // app persistence
} else {
    // outcome.UnavailableReason 决定换新 nonce、等待或终止。
}
// 008 never produces a payment credential and never closes a pool. If the
// seller never submitted custody, the buyer waits or broadcasts its presigned
// refund after nLockTime (BuildMaturedRefund).
// 时间无关恢复：Sign 时以新 Facts 复查 deadline。
func RestorePreparedArbitration(rawKind8 []byte, fee protocol.Satoshis) (*PreparedArbitration, error)

// 构造时固定的压缩公钥。
func (w *Workflow) PublicKey() []byte

```

In every ending the SDK computes and verifies only; sending, broadcasting,
persisting, retrying, and reconciling are application actions.
