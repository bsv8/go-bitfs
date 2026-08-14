---
id: role-workflow-api
title: 03 · 角色工作流 API
---

# 03 · 角色工作流 API

返回 [SDK API 框架入口](sdk-api-framework-design.md)。

当前实现入口分别是 `buyer.NewWorkflow(buyer.WorkflowConfig{...})`、`seller.NewWorkflow(seller.WorkflowConfig{...})` 和 `arbitration.NewWorkflow(arbitration.WorkflowConfig{...})`。下文保留为角色级调用顺序说明；细节以包中的实际类型和方法为准。

本页描述面向应用开发者的角色门面。它们不持有网络连接：每个方法返回应由应用发送给下一参与方的结构化报文或原始交易。签名、存储、节点等依赖见[外部钩子与数据类型](external-hooks-and-data-types.md)。

## 买方 API

```go
// package buyer
// Workflow 只依赖注入的端口。NewWorkflow 必须验证所有必需端口非 nil。
type Workflow struct { /* 未公开字段 */ }

type WorkflowConfig struct {
    Signer            pool.Signer
    QuoteVerifier     bitfs.QuoteTermsSignatureVerifier
    SignatureVerifier bitfs.ContentTermsSignatureVerifier
    Clock             func() time.Time
    Quotes            QuoteStore
    Pools             pool.PoolStore
    Opening           pool.BuyerPoolOpeningHooks
    Participants      pool.ParticipantVerifier
    Node              pool.NonFinalPoolNode
    Transactions      pool.BuyerPoolPort
    ContentSink       ContentSink
    SeedSource        SeedSource
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error)

// AcceptQuote 验证 001 并保存原始报价。之后 RequestContent 和 AcceptDelivery 才能按哈希取回它。
func (workflow *buyer.Workflow) AcceptQuote(
    ctx context.Context,
    quote *bitfs.SignedFileQuote,
) (*bitfs.FileQuoteTerms, error)

// PreparePoolOpening 接受买方钱包准备好的 FundingTx，构造初始远期 RefundTx 并签出买方退款签名。
// 返回的请求是 002 的 PoolRefundPresignRequest，应发送给卖方；此时绝不可广播 FundingTx。
func (workflow *buyer.Workflow) PreparePoolOpening(
    ctx context.Context,
    input pool.OpeningInput,
) (*pool.RefundPresignRequest, error)

// AcceptRefundPresign 验证卖方退款签名、保存完整开池证明，并记录初始退款状态。
// 成功意味着买方侧开池完成；卖方尚未必然提交 FundingTx。
func (workflow *buyer.Workflow) AcceptRefundPresign(
    ctx context.Context,
    request *pool.RefundPresignRequest,
    response *pool.RefundPresignResponse,
    fundingTx []byte,
) (*pool.Reference, error)

// BuildFundingTxDelivery 在买方保存完整开池证明后，生成可发送给卖方的 002 报文。
func (workflow *buyer.Workflow) BuildFundingTxDelivery(
    fundingTx []byte,
) (*pool.FundingTxDelivery, error)

// RequestContent 选择一份已验证报价、一个可用池和一个内容哈希，创建 003。
// 它只读取该池的最后已接受状态。卖方是否存在进行中请求由卖方在处理 003 时判定。
func (workflow *buyer.Workflow) RequestContent(
    ctx context.Context,
    input ContentRequestInput,
) (*bitfs.SignedContentRequest, error)

// AcceptDelivery 验证并可选保存 004 内容，然后按报价价格构造、签署 005。
// 返回的 PaymentUpdate 应发送给卖方；本函数不自行把 update 提交到节点。
func (workflow *buyer.Workflow) AcceptDelivery(
    ctx context.Context,
    request *bitfs.SignedContentRequest,
    delivery *bitfs.SignedContentDelivery,
) (*pool.PaymentUpdate, error)

// RefundAfterExpiry 将开池证明中分离保存的双方签名合并到退款交易后提交。
// 若节点已保存更高付款状态，节点会拒绝该旧退款；这不是 SDK 可绕过的失败。
func (workflow *buyer.Workflow) RefundAfterExpiry(ctx context.Context, spendTxID pool.Hash32) (pool.Hash32, error)

// BuildImmediateClose 构造空解锁协商关闭交易并返回 Buyer detached signature。
// 交易的 nSequence 与 nLockTime 都为 0xffffffff；它不适用于单方到期退款。
func (workflow *buyer.Workflow) BuildImmediateClose(
    ctx context.Context,
    input pool.CloseInput,
) (*pool.UnsignedPayment, []byte, error)

// SubmitImmediateClose 提交卖方已补足签名的最终交易。
// 它只调用 SubmitFinal，不会写入或覆盖非最终交易池状态。
func (workflow *buyer.Workflow) SubmitImmediateClose(
    ctx context.Context,
    close *pool.SignedPayment,
) (pool.Hash32, error)
```

`ContentRequestInput` 至少包含：已验证报价、`Pool.Reference`（其中包含 `SpendTxID` 和当前 `BasePaymentSequence`）、选定仲裁公钥、`ContentRef` 和交付期限。它不接收块索引、报价价格或任意卖方金额。

## 卖方 API

卖方 API 把最危险的“先交付、后付款”窗口封装在一个调用中：先验证 003，再原子加门闩，最后读取内容并签出 004。调用者不得绕过 `DeliverRequestedContent` 而自行交付。

```go
// package seller
type WorkflowConfig struct {
    Signer            pool.Signer
    SignatureVerifier bitfs.ContentTermsSignatureVerifier
    QuoteVerifier     bitfs.QuoteTermsSignatureVerifier
    Clock             func() time.Time
    Quotes            QuoteStore
    Pools             pool.PoolStore
    OpeningHooks      pool.SellerPoolOpeningHooks
    Pending           pool.PendingRequestStore
    Content           ContentSource
    Transactions      pool.SellerPoolPort
    Participants      pool.ParticipantVerifier
    Node              pool.NonFinalPoolNode
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error)

// CreateQuote 创建、签署并保存 001。
// 返回值可经任意调用方网络通道发送给指定买方。
func (workflow *seller.Workflow) CreateQuote(
    ctx context.Context,
    draft bitfs.FileQuoteTerms,
    recommendedFilename string,
) (*bitfs.SignedFileQuote, error)

// PresignPoolOpening 验证 002 请求、签署初始退款交易并先保存待激活开池证明。
// 返回响应后，卖方仍没有资金池，不能据此交付内容。
func (workflow *seller.Workflow) PresignPoolOpening(
    ctx context.Context,
    request *pool.RefundPresignRequest,
) (*pool.RefundPresignResponse, error)

// AcceptPoolFunding 验证 FundingTx 与已保存证明一致，保存完整证明并提交 FundingTx。
// 只有节点提交成功后，卖方才把池视为可用于 003。
func (workflow *seller.Workflow) AcceptPoolFunding(
    ctx context.Context,
    delivery *pool.FundingTxDelivery,
) (*pool.OpeningProof, error)

// DeliverRequestedContent 验证 003、报价、池、公钥、仲裁者、余额和当前序号。
// 它先原子获得该池门闩，之后读取内容、计算哈希、签出 004 并返回。
// 已有门闩时返回 ErrPoolBusy；请求序号不是最新时返回 ErrStalePaymentSequence。
func (workflow *seller.Workflow) DeliverRequestedContent(
    ctx context.Context,
    request *bitfs.SignedContentRequest,
) (*bitfs.SignedContentDelivery, error)

// AcceptPayment 验证 005 的原始交易、买方签名、输入、递增 nSequence 和累计金额；
// 卖方签名并提交到非最终交易池。仅节点确认接受后才保存新状态并释放对应门闩。
// 返回值是提交后的状态，不是发送给买方的额外确认报文。
func (workflow *seller.Workflow) AcceptPayment(
    ctx context.Context,
    payment *pool.PaymentUpdate,
) (*pool.PaymentState, error)

// SignImmediateClose 验证空解锁关闭交易和 Buyer detached signature，
// 使用工作流配置中的卖方签名能力补足 Seller detached signature，
// 并返回可立即提交的完整交易。它不自行广播；signer 参数仅为接口兼容保留。
func (workflow *seller.Workflow) SignImmediateClose(
    ctx context.Context,
    close *pool.UnsignedPayment,
    buyerSignature []byte,
    signer pool.Signer,
) (*pool.SignedPayment, error)

// BuildArbitrationRequestFromAuthorization 依据最终 003 授权和当前状态构造空解锁候选，并签 Seller。
func (workflow *seller.Workflow) BuildArbitrationRequestFromAuthorization(
    ctx context.Context,
    proof *pool.OpeningProof,
    authorization *bitfs.SignedContentRequest,
    latest *pool.PaymentState,
) (*arbitration.ArbitrationRequest, error)

// SubmitArbitratedPayment 合并仲裁者签名，并通过非最终节点提交同一累计状态。
func (workflow *seller.Workflow) SubmitArbitratedPayment(
    ctx context.Context,
    request *arbitration.ArbitrationRequest,
    response *arbitration.ArbitrationResponse,
) (*pool.PaymentState, error)
```

## 仲裁者 API

仲裁者接收完整证据而非内部查询买卖双方。它不裁定文件是否交付，也不重算报价金额。

```go
// package arbitration
type WorkflowConfig struct {
    Signer                pool.Signer
    Pool                  PoolPort
    AuthorizationVerifier bitfs.ContentTermsSignatureVerifier
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error)

// 这是应用层适配器，不是 SDK 类型；卖方应用可以通过 HTTP、消息队列或本地调用实现。
type ArbiterClient interface {
    SignPayment(ctx context.Context, request *arbitration.ArbitrationRequest) (*arbitration.ArbitrationResponse, error)
}

// SignPayment 验证 007 证据包中的开池证明、最终授权和空解锁候选交易。
// 校验通过后只返回对该精确交易的仲裁者签名；不返回批准状态、金额或数据库 ID。
func (workflow *arbitration.Workflow) SignPayment(
    ctx context.Context,
    request *arbitration.ArbitrationRequest,
) (*arbitration.ArbitrationResponse, error)
```

## 完整业务流程示例

下面用一次“买方购买卖方文件”的完整流程串起主要 API。代码是应用层伪代码；钱包、数据库、内容源、MultisigPool 适配器和节点适配器均由应用实现并注入 SDK。

### 1. 为三个角色创建各自的能力

一个 `Signer` 只代表一个角色的一把私钥。验证器没有自己的公钥；调用时由 SDK 从报价、003 授权或开池证明中取出被验证者的公钥，再传给验证回调。

```go
buyerSigner   := app.BuyerSigner()   // implements pool.Signer
sellerSigner  := app.SellerSigner()  // implements pool.Signer
arbiterSigner := app.ArbiterSigner() // implements pool.Signer

// These callbacks implement the underlying signature scheme. The pubkey is
// supplied by the credential being verified; the verifier has no role key.
verifyQuote := app.VerifyQuote       // bitfs.QuoteTermsSignatureVerifier
verifyTerms := app.VerifyTerms       // bitfs.ContentTermsSignatureVerifier

buyerWorkflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{
    Signer:            buyerSigner,
    QuoteVerifier:     verifyQuote,
    SignatureVerifier: verifyTerms,
    Clock:             time.Now,
    Quotes:            buyerQuotes,
    Pools:             buyerPools,
    Opening:           buyerOpeningHooks,
    Participants:      participantVerifier,
    Transactions:      buyerPoolPort,
    Node:              buyerNode,
    ContentSink:       buyerContentSink,
    SeedSource:        buyerSeedSource,
})
must(err)

sellerWorkflow, err := seller.NewWorkflow(seller.WorkflowConfig{
    Signer:            sellerSigner,
    QuoteVerifier:     verifyQuote,
    SignatureVerifier: verifyTerms,
    Clock:             time.Now,
    Quotes:            sellerQuotes,
    Pools:             sellerPools,
    OpeningHooks:      sellerOpeningHooks,
    Pending:           sellerPending,
    Content:           sellerContent,
    Transactions:      sellerPoolPort,
    Participants:      participantVerifier,
    Node:              sellerNode,
})
must(err)

arbiterWorkflow, err := arbitration.NewWorkflow(arbitration.WorkflowConfig{
    Signer:                arbiterSigner,
    Pool:                  arbiterPoolPort,
    AuthorizationVerifier: verifyTerms,
})
must(err)
```

应用传输层只负责携带路由 `Kind` 和原始 CBOR。下面的辅助函数表示这条规则；真实应用可以把返回值放进 HTTP、WebSocket、消息队列或本地 RPC。

```go
func makePacket(kind wire.Kind, value any) wire.Packet {
    packet, err := wire.Marshal(kind, value)
    must(err)
    return packet
}

func transmit(packet wire.Packet) (wire.Kind, []byte) {
    // Send both values through the application transport. The receiver uses
    // the Kind to select the matching typed Unmarshal helper.
    return packet.Kind, append([]byte(nil), packet.CBOR...)
}
```

### 2. 卖方创建报价，买方验收报价

```go
quote, err := sellerWorkflow.CreateQuote(ctx, quoteDraft, "report.pdf")
must(err)

_, quoteCBOR := transmit(makePacket(wire.Quote, quote))
receivedQuote, err := wire.UnmarshalQuote(quoteCBOR)
must(err)

quoteTerms, err := buyerWorkflow.AcceptQuote(ctx, receivedQuote)
must(err)
quoteHashRaw, err := bitfs.FileQuoteTermsHash(receivedQuote.TermsCBOR)
must(err)
quoteHash := bitfs.Hash32(quoteHashRaw)
_ = quoteTerms // 已验证的报价条款；后续请求按 quoteHash 引用它。
```

这里发生了两次不同的动作：卖方的 `Signer` 签署报价，买方的 `QuoteVerifier` 验证报价中的 `SellerPubkey`。买方不需要拥有卖方的私钥。

### 3. 买方和卖方完成费用池开立

`fundingTx` 是买方钱包准备好的原始资金交易。此时只能先预签退款交易，不能提前广播资金交易。

```go
arbiterPubkey, err := arbiterSigner.PublicKey(ctx)
must(err)

fundingTx := app.BuildFundingTx()
presign, err := buyerWorkflow.PreparePoolOpening(ctx, pool.OpeningInput{
    FundingTx:            fundingTx,
    PoolOutputIndex:      0,
    ExpiryLockTime:       app.RefundExpiryLockTime(),
    MinerFeeRateSatPerKB: app.MinerFeeRate(),
    SellerPubKey:         receivedQuote.SellerPubkey,
    ArbiterPubKey:        arbiterPubkey,
})
must(err)

_, sellerPresignCBOR := transmit(makePacket(wire.PoolRefundPresignRequest, presign))
sellerPresign, err := wire.UnmarshalPoolRefundPresignRequest(sellerPresignCBOR)
must(err)

presignResponse, err := sellerWorkflow.PresignPoolOpening(ctx, sellerPresign)
must(err)

_, buyerResponseCBOR := transmit(makePacket(wire.PoolRefundPresignResponse, presignResponse))
buyerResponse, err := wire.UnmarshalPoolRefundPresignResponse(buyerResponseCBOR)
must(err)

// This durably records the complete opening proof and initial payment state.
reference, err := buyerWorkflow.AcceptRefundPresign(
    ctx, presign, buyerResponse, fundingTx,
)
must(err)

fundingDelivery, err := buyerWorkflow.BuildFundingTxDelivery(fundingTx)
must(err)
_, fundingCBOR := transmit(makePacket(wire.PoolFundingTxDelivery, fundingDelivery))
sellerFunding, err := wire.UnmarshalPoolFundingTxDelivery(fundingCBOR)
must(err)

// Only now does the seller verify and submit the funding transaction.
_, err = sellerWorkflow.AcceptPoolFunding(ctx, sellerFunding)
must(err)
```

`PreparePoolOpening` 和 `PresignPoolOpening` 使用的是费用池开立钩子；底层 MultisigPool 需要实际私钥来计算交易签名，因此这部分能力通常由 `PrivateKeyProvider` 封装在 pool adapter 中。它和凭证用的通用 `Signer` 是两个层次。

### 4. 买方请求内容，卖方交付内容

以下示例请求一个 block，因此买方的 `SeedSource` 必须能提供报价承诺的 seed。请求 seed 时可使用 `ContentType: bitfs.ContentSeed`，不需要 `SeedSource`。

```go
contentHash := app.RequestedBlockHash()
request, err := buyerWorkflow.RequestContent(ctx, buyer.ContentRequestInput{
    QuoteTermsHash:        quoteHash,
    Pool:                  reference,
    SelectedArbiterPubKey: arbiterPubkey,
    Content: bitfs.ContentRef{
        Type: bitfs.ContentBlock,
        Hash: contentHash,
    },
    ContentSize:      app.ExpectedBlockSize(),
    DeliveryDeadline: bitfs.UnixSeconds(time.Now().Add(time.Hour).Unix()),
})
must(err)

_, requestCBOR := transmit(makePacket(wire.ContentRequest, request))
sellerRequest, err := wire.UnmarshalContentRequest(requestCBOR)
must(err)

// This call verifies 003, acquires the seller-side pending-request latch,
// reads ContentSource, verifies the payload, and signs 004.
delivery, err := sellerWorkflow.DeliverRequestedContent(ctx, sellerRequest)
must(err)

_, deliveryCBOR := transmit(makePacket(wire.ContentDelivery, delivery))
buyerDelivery, err := wire.UnmarshalContentDelivery(deliveryCBOR)
must(err)
```

买方的 `RequestContent` 使用自己的 `Signer` 签 003；卖方的 `SignatureVerifier` 验证这个签名时，使用报价中约定的买方公钥。卖方随后用自己的 `Signer` 签 004；买方验收时使用报价中的卖方公钥。

### 5. 买方验收交付，卖方接受累计付款

```go
payment, err := buyerWorkflow.AcceptDelivery(ctx, request, buyerDelivery)
must(err)

_, paymentCBOR := transmit(makePacket(wire.CumulativePayment, payment))
sellerPayment, err := wire.UnmarshalPaymentUpdate(paymentCBOR)
must(err)

// The seller verifies the exact buyer signature, adds its own signature,
// submits the same cumulative state to the non-final pool, then persists it.
accepted, err := sellerWorkflow.AcceptPayment(ctx, sellerPayment)
must(err)
_ = accepted
```

这里没有额外的“付款成功”协议报文。卖方以节点对同一交易的接受结果为准；应用如果需要通知买方，可以自行发送状态通知，但不能把通知当成链上或费用池接受证明。买方若要继续构造协商关闭，必须先通过节点查询或应用同步，把已接受状态写入自己的 `buyerPools`。

### 6. 付款异常时的仲裁分支

下面是替代 `AcceptPayment` 的分支，不应与正常付款路径同时执行。卖方依据已经签名的 003 和自己保存的最新池状态构造 007，仲裁者只验证证据并添加自己的交易签名。

```go
proof, err := sellerPools.LoadOpeningProof(ctx, reference.SpendTxID)
must(err)
latest, err := sellerPools.LoadAcceptedPayment(ctx, reference.SpendTxID)
must(err)

arbitrationRequest, err := sellerWorkflow.BuildArbitrationRequestFromAuthorization(
    ctx, proof, sellerRequest, latest,
)
must(err)

_, arbRequestCBOR := transmit(makePacket(wire.ArbitrationRequest, arbitrationRequest))
arbiterRequest, err := wire.UnmarshalArbitrationRequest(arbRequestCBOR)
must(err)

arbitrationResponse, err := arbiterWorkflow.SignPayment(ctx, arbiterRequest)
must(err)

_, arbResponseCBOR := transmit(makePacket(wire.ArbitrationResponse, arbitrationResponse))
arbiterResponse, err := wire.UnmarshalArbitrationResponse(arbResponseCBOR)
must(err)

arbitrated, err := sellerWorkflow.SubmitArbitratedPayment(
    ctx, arbiterRequest, arbiterResponse,
)
must(err)
_ = arbitrated
```

仲裁者的 `AuthorizationVerifier` 验证的是 003 中的买方签名；仲裁者自己的 `Signer` 只负责给经过验证的候选交易添加仲裁者签名。

### 7. 另外两个结束分支：协商关闭和到期退款

协商关闭和到期退款也是替代路径，不是上面正常付款后的必经步骤。协商关闭需要双方共同签名，但不新增一个 CBOR `CloseRequest`。下面假设 `buyerPools` 已经通过节点或应用同步保存了最新被接受状态：

```go
opening, err := buyerPools.LoadOpeningProof(ctx, reference.SpendTxID)
must(err)
latestPayment, err := buyerPools.LoadAcceptedPayment(ctx, reference.SpendTxID)
must(err)

unsignedClose, buyerSig, err := buyerWorkflow.BuildImmediateClose(ctx, pool.CloseInput{
    Opening:              opening,
    Latest:               latestPayment,
    SellerAmountAfterSat: latestPayment.SellerAmountSat,
})
must(err)

closed, err := sellerWorkflow.SignImmediateClose(ctx, unsignedClose, buyerSig, sellerSigner)
must(err)

_, err = buyerWorkflow.SubmitImmediateClose(ctx, closed)
must(err)
```

如果费用池已经过期且没有更高的已接受付款状态，买方可以走单方退款路径：

```go
_, err = buyerWorkflow.RefundAfterExpiry(ctx, reference.SpendTxID)
must(err)
```

整个示例中，应用负责实现依赖和传输；工作流负责角色顺序、精确 CBOR、签名绑定、状态检查和提交时机。应用不得用 JSON 重编码这些对象，也不得在传输层添加决定金额或支付序号的字段。
