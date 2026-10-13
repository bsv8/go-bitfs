---
id: role-workflow-api
title: 03 · Role pure-function API
---

# 03 · Role pure-function API

SDK = 无状态计算器 + 验钞机：每个入口只接收原始报文字节、普通证据包与一次调用
专用的受约束 `protocol.Signer`，返回原始报文字节或普通证据包。SDK 不持有跨步骤
对象、不保存进度、不定价、不碰钱包、不广播、不读时钟、不访问存储。算价公式与
证据校验留在 SDK，买卖双方必须独立算出同一结果。

证据包是普通数据：只含原始字节与明确字段，可序列化、可复制、无行为。安全由
「每个步骤都从原始证据全量重验」保证，而不是由对象不可构造保证。应用负责持久化
每个入口返回的 exact bytes 与证据包、推进自己的状态机，并在广播前自行决策。

签名能力只经 `protocol.NewPrivateKeySigner` 进入并随每次调用传入；SDK 立即绑定
并自验 Signer 公钥，签名返回前不产生任何 wire 或本地状态。

Recommended application ordering for every step:

```
load（按 RefundTemplateTxID / 授权 ID 加载应用自己的原始 bytes 与证据包）
→ SDK 纯函数 compute/verify（显式传入全部前序原始证据与 Facts）
→ persist exact bytes 与证据包（先保存后发送）
→ send/broadcast → record outcome
```

## Buyer API

```go
// package buyer

// AcceptQuote 严格解析 exact Kind 1 bytes，验签与过期判断通过后返回不可变
// VerifiedQuote。它不绑定调用方身份；买方应用必须自行比较
// Terms().BuyerPublicKey 与本地身份，再决定是否购买。
func AcceptQuote(facts protocol.Facts, rawKind1 []byte) (quote *content.VerifiedQuote, err error)

// PrepareOpening 构造并签署 exact Kind 2 预签请求：先用 exact Kind 1 报价条款
// 绑定买方身份、卖方公钥与受支持仲裁方，再返回待发送 Artifact 与必须
// 先持久化的普通证据包。资金交易原文只存在于证据包，SDK 不持久化。
func PrepareOpening(ctx context.Context, input PrepareOpeningInput, signer protocol.Signer) (outbound wire.Artifact, evidence BuyerOpeningEvidence, err error)

// CompleteOpening 用保存的普通证据包验收 exact Kind 3：重派生池关联 ID 并拒绝
// 任何错配，验卖方预签，产出完整开池证据包与初始池证据包。
func CompleteOpening(opening BuyerOpeningEvidence, rawKind3 []byte) (completed BuyerOpeningEvidence, poolEvidence BuyerPoolEvidence, err error)

// PrepareFundingDelivery 把完整开池证据包携带的资金交易打包成 exact Kind 4
// Artifact；不广播资金交易——广播边界属于应用。
func PrepareFundingDelivery(evidence BuyerPoolEvidence) (outbound wire.Artifact, err error)

// PrepareContentRequest 验证报价/池/批次上下文/聚合价格/余额后签署 exact
// Kind 5：返回待发送 Artifact 与必须先持久化的普通授权证据包。
func PrepareContentRequest(ctx context.Context, facts protocol.Facts, input RequestContentInput, signer protocol.Signer) (outbound wire.Artifact, evidence BuyerAuthorizationEvidence, err error)

// VerifyDelivery 验收 exact Kind 6 并产生整批唯一的最小 exact Kind 7 凭证：
// 先验 payload 与 seed 归属，再签 Kind 7；不产生“已付款”状态。
func VerifyDelivery(ctx context.Context, facts protocol.Facts, input VerifyDeliveryInput, signer protocol.Signer) (payloads [][]byte, outbound wire.Artifact, err error)

// PrepareClose 从调用方选定的基准池证据与目标金额构造未签名关闭 candidate 和
// 买方 detached 签名；SDK 不判断目标金额是否符合订单或账本。返回未签名
// candidate 原文与买方签名。
func PrepareClose(ctx context.Context, facts protocol.Facts, input PrepareCloseInput, signer protocol.Signer) (unsignedRaw []byte, buyerSignature []byte, err error)

// VerifyCompletedClose 验证卖方完整关闭交易在给定开池证据下密码学、结构与
// 交易关系全部正确，返回不可变 Complete 结果；不声称已广播或已确认。
func VerifyCompletedClose(input VerifyCompletedCloseInput) (transaction *pool.VerifiedSignedTransaction, err error)

// BuildMaturedRefund 在显式事实判定退款到期后合并双方退款签名，返回可广播的
// verified refund transaction；是否广播由应用决定，不调用任何 Signer。
func BuildMaturedRefund(facts protocol.Facts, evidence BuyerPoolEvidence) (transaction *pool.VerifiedSignedTransaction, err error)

// RequestArbitratedContent 为一条托管记录构造 exact Kind 10 Artifact：默认入口
// 由 SDK 生成安全随机 nonce；网络超时重试必须原样重放已持久化的 Artifact，
// 绝不能重新调用本方法生成新 nonce。
func RequestArbitratedContent(ctx context.Context, input RetrievalRequestInput, signer protocol.Signer) (outbound wire.Artifact, err error)

// VerifyArbitratedContent 时间无关地验收 exact Kind 10/11：available 分支额外
// 复核 payload 归属与价格；unavailable 分支作为已验签协议结果返回，不是 error。
// Kind 10 的买方签名直接对照开池证据中的买方公钥验证，不需要 Signer。
func VerifyArbitratedContent(ctx context.Context, input ArbitratedContentInput) (result *ArbitratedContentResult, err error)
```

普通证据包（只含原始字节，可序列化；省略 `LatestPaymentRawTx` 表示初始退款状态）：

```go
type BuyerOpeningEvidence struct {
    RawKind2              []byte // 买方发出的 exact Kind 2
    RawKind3              []byte // 卖方返回的 exact Kind 3（PrepareOpening 阶段为空）
    FundingTransactionRaw []byte // 买方私密资金交易原文
}

type BuyerPoolEvidence struct {
    Opening            *pool.OpeningProof // 完整开池证明（普通数据）
    LatestPaymentRawTx []byte             // 链上最新完整付款交易原文；省略=初始状态
}

type BuyerAuthorizationEvidence struct {
    RawKind1 []byte // exact Kind 1 报价
    RawKind5 []byte // exact Kind 5 付款授权
}
```

## Seller API

```go
// package seller

// CreateQuote 以单一 QuoteDraft 签署确定性 Kind 1 条款：先 sanitize 文件名再
// 编码与签名，返回待发送 exact Kind 1 与最终规范化条款（展示实际签署值）。
func CreateQuote(ctx context.Context, facts protocol.Facts, signer protocol.Signer, draft QuoteDraft) (outbound wire.Artifact, terms *content.FileQuoteTerms, err error)

// PreparePresign 顺序固定：解析 → 角色/模板/费率 → 买方退款签名 → 才调用
// Signer；金额从退款模板推导。返回待发送 exact Kind 3 与必须先持久化的普通
// 证据包。
func PreparePresign(ctx context.Context, rawKind2 []byte, signer protocol.Signer) (outbound wire.Artifact, evidence SellerOpeningEvidence, err error)

// VerifyFunding 用预签证据包验收 exact Kind 4：重建完整开池证明，验证资金交易
// output[0] 金额/脚本与退款模板重建一致，并解析初始链上付款状态。
func VerifyFunding(rawKind4 []byte, opening SellerOpeningEvidence) (fundingRaw []byte, evidence SellerPoolEvidence, err error)

// InspectDeliveryRequest 在读取内容仓库前预检 exact Kind 5：验证报价、开池、买家
// 签名、截止时间、当前付款状态、序号与容量，返回授权 ID、目标序号和有序哈希。
// 此摘要不证明 payload 有效；应用读取后仍须调用 PrepareDelivery 完成全量验收。
func InspectDeliveryRequest(facts protocol.Facts, input InspectDeliveryRequestInput) (summary *DeliveryRequestSummary, err error)

// PrepareDelivery 完成 quote/opening/时序/序号/容量/价格/payload 全量校验后
// 签署 exact Kind 6（发送前应用必须先持久化 payload 与证据包）。
func PrepareDelivery(ctx context.Context, facts protocol.Facts, input DeliveryInput, signer protocol.Signer) (outbound wire.Artifact, evidence SellerDeliveryEvidence, err error)

// CompletePayment 从输入重建池状态：验证序号 +1、金额不倒退、授权 ID 与本方
// 已发 exact Kind 6 交付证据逐字节一致、容量足够，验过买方签名后补签并合并
// 完整交易。
func CompletePayment(ctx context.Context, facts protocol.Facts, input CompletePaymentInput, signer protocol.Signer) (rawTransaction []byte, nextPool SellerPoolEvidence, err error)

// CompleteClose 校验买方关闭 candidate 结构与角色签名后补签并合并完整交易；
// 是否广播由应用决定。
func CompleteClose(ctx context.Context, facts protocol.Facts, input CompleteCloseInput, signer protocol.Signer) (rawTransaction []byte, err error)

// PrepareArbitration 验证本地开池、买方授权与本方已发交付后，签署紧凑 Claim
// 证据并返回 exact Kind 8 与独立计算的 Claim ID。
func PrepareArbitration(ctx context.Context, facts protocol.Facts, input PrepareArbitrationInput, signer protocol.Signer) (outbound wire.Artifact, claimID protocol.ArbitrationClaimID, err error)

// CompleteArbitratedPayment 从 exact Kind 8/9 完整验证托管收款路径：独立重建
// paid candidate、验证回执消息签名与仲裁交易签名，然后补签卖方交易签名并
// 合并完整交易。
func CompleteArbitratedPayment(ctx context.Context, facts protocol.Facts, input CompleteArbitratedPaymentInput, signer protocol.Signer) (rawTransaction []byte, err error)
```

普通证据包：

```go
type SellerOpeningEvidence struct {
    RawKind2 []byte // 买方 exact Kind 2 请求
    RawKind3 []byte // 卖方发出的 exact Kind 3 响应
}

type SellerPoolEvidence struct {
    Opening               *pool.OpeningProof // 完整开池证明（普通数据）
    FundingTransactionRaw []byte             // 资金交易原文副本
    LatestPaymentRawTx    []byte             // 链上最新完整付款交易原文；省略=初始状态
}

type SellerDeliveryEvidence struct {
    RawKind1 []byte // exact Kind 1 报价
    RawKind5 []byte // 买方 exact Kind 5 授权
    RawKind6 []byte // 卖方发出的 exact Kind 6 交付
}
```

## Arbiter API

```go
// package arbiter

// PrepareArbitration 对 exact Kind 8 托管请求做完整时间相关证据验证但绝不
// 签名：Claim 结构、买卖双方签名、逐 payload 哈希、按显式正仲裁费独立重建
// candidate、交付截止与退款锁定门禁。返回可直接持久化的普通证据包。
func PrepareArbitration(facts protocol.Facts, rawKind8 []byte, fee protocol.Satoshis) (prepared *PreparedArbitrationEvidence, err error)

// SignPreparedArbitration 从普通证据包重新验证全部证据后才签名：Claim ID、
// 费用、角色、deadline（用本次显式 Facts.Now）与 candidate 逐项重算比对，
// 先签仲裁交易，再编码回执并自验统一回执消息签名。
func SignPreparedArbitration(ctx context.Context, facts protocol.Facts, prepared PreparedArbitrationEvidence, signer protocol.Signer) (signed *SignedArbitrationEvidence, err error)

// AuthenticateRetrieval 仅完成 Kind 10 买方鉴权：时间无关，不需要 Kind 9 存在。
// 持有 storedKind8 记录的一方即托管仲裁方。
func AuthenticateRetrieval(rawKind10 []byte, storedKind8 []byte) error

// BuildUnavailableRetrieval 构造并签署 valid exact Kind 11 unavailable Artifact：
// reason：0 未收到、1 未就绪、2 托管已丢失。
func BuildUnavailableRetrieval(ctx context.Context, requestID protocol.ContentRetrievalRequestID, reason arbitration.ContentRetrievalUnavailableReason, signer protocol.Signer) (outbound wire.Artifact, err error)

// BuildAvailableRetrieval 构造并签署 valid exact Kind 11 available Artifact，
// 直接附带经 content_payloads_id 绑定的 verified exact payloads。
func BuildAvailableRetrieval(ctx context.Context, requestID protocol.ContentRetrievalRequestID, custody *arbitration.VerifiedCustodiedContent, signer protocol.Signer) (outbound wire.Artifact, err error)

// CompleteArbitratedPayment 从签名证据包重建 paid candidate 并合并
// Seller/Arbiter 双签名，返回完整仲裁交易原文。
func CompleteArbitratedPayment(signed SignedArbitrationEvidence, sellerSignature []byte) (rawTransaction []byte, err error)
```

普通证据包：

```go
type PreparedArbitrationEvidence struct {
    RawKind8     []byte                        // exact Kind 8
    CandidateRaw []byte                        // 独立重建的未签名仲裁交易原文
    ArbitrationClaimID protocol.ArbitrationClaimID // SHA-256(exact Claim CBOR)
    FeeSatoshis  protocol.Satoshis             // 本次仲裁的绝对仲裁费
}

type SignedArbitrationEvidence struct {
    Prepared                    PreparedArbitrationEvidence // 冻结的 Prepare 证据
    Outbound                    wire.Artifact                // 待发送 exact Kind 9
    ArbiterTransactionSignature []byte                       // 仲裁方交易签名
}
```

## Pool API (unchanged)

池与交易纯函数继续由 `pool` 包提供：`MultisigPoolEngine.BuildOpeningState`、
`VerifyOpeningEvidence`、`BuildState`、`SignState`、`MergeBuyerSeller`、
`MergeSellerArbiter`、`pool.VerifyPaymentState`、`pool.TransactionID` 与
`pool.ParsePaymentState`。
