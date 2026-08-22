---
id: role-workflow-api
title: 03 · 角色 workflow API
---

# 03 · 角色 workflow API

每个 workflow 只持有构造时传入的官方 BSV 私钥。方法从不加载或保存状态、从不发送报文、从不广播交易、也从不查询节点；每个公开入口在内部读取一次系统 UTC，并把区块高度作为显式参数传入。下文对每个方法列出其 wire 输入、本地输入、wire 输出、本地输出与无副作用保证。应用以 `RefundTemplateTxID` 为键持久化每个返回的本地值，按池串行化并发工作，发送 wire 报文，并通过自己的节点适配器广播原始交易。

每个步骤都遵循的应用侧推荐顺序：

```
load（按 RefundTemplateTxID） → SDK compute/verify → persist intent/result
→ send/broadcast → record outcome
```

## Buyer API

```go
// package buyer
type WorkflowConfig struct {
    PrivateKey *ec.PrivateKey // 官方 BSV Go SDK 私钥
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error)

// BuyerOpeningState 是买方私有本地状态（wire：无；local：全部）。
type BuyerOpeningState struct {
    RefundTemplateTxID pool.RefundTemplateTxID
    Request      *pool.RefundPresignRequest
    FundingTx    []byte // 绝不进入 FundingTxDelivery 以外的任何报文
}

// PoolOpeningPreparation 是 PreparePoolOpening 的复合结果。
type PoolOpeningPreparation struct {
    Request *pool.RefundPresignRequest // 发送给卖方的 wire 报文
    State   *BuyerOpeningState         // 发送前必须保存的本地状态
}

// RefundPresignAcceptance 是 AcceptRefundPresign 的复合结果。
type RefundPresignAcceptance struct {
    Reference      pool.Reference     // 池 ID + 当前已接受序号
    Opening        *pool.OpeningProof // 含 FundingTx 的完整 proof（本地）
    InitialPayment *pool.PaymentState // 初始退款状态（本地）
}

// VerifiedDelivery 是 AcceptDelivery 的复合结果。
type VerifiedDelivery struct {
    Payloads [][]byte            // 已验证的 payload 批次，顺序与 003 hashes 一致（本地，需保存）
    Update   *pool.PaymentUpdate // 整个批次唯一的 wire 付款更新
}

// AcceptQuote 在入口处读取一次系统 UTC 来验证签名、条款和有效期。
// wire 输入：签名的 001。本地输出：接受的条款。不持久化。
func (workflow *Workflow) AcceptQuote(ctx context.Context, quote *bitfs.SignedFileQuote) (*bitfs.FileQuoteTerms, error)

// PreparePoolOpening 构造并签名通用 002 退款证据。
// wire 输入：无。本地输入：pool.OpeningInput。
// 同时返回 wire 请求与必须先保存的私有状态。
func (workflow *Workflow) PreparePoolOpening(ctx context.Context, input pool.OpeningInput) (*PoolOpeningPreparation, error)

// AcceptRefundPresign 用显式提供的已保存开池状态验证 0202 响应；
// 重新派生 RefundTemplateTxID 并拒绝任何错配。
// wire 输入：0202 响应。本地输入：保存的 BuyerOpeningState。
func (workflow *Workflow) AcceptRefundPresign(ctx context.Context, state *BuyerOpeningState, response *pool.RefundPresignResponse) (*RefundPresignAcceptance, error)

// BuildFundingTxDelivery 把已验证 proof 携带的资金交易打包为 0204 wire 交付。
// 调用方显式传入 proof；SDK 不按哈希加载任何东西。
func (workflow *Workflow) BuildFundingTxDelivery(ctx context.Context, opening *pool.OpeningProof) (*pool.FundingTxDelivery, error)

// BuildContentRequest 验证报价/开池归属/上一状态的绑定、批次成员上下文、
// 聚合价格与余额，然后用本 workflow 的私钥签名 003 请求。
// 系统 UTC 在入口处读取一次；区块高度由输入提供。不读取内容；
// 内容类型完全由证据推导，批量价格逐项 checked-add。
func (workflow *Workflow) BuildContentRequest(ctx context.Context, quote *bitfs.SignedFileQuote, opening *pool.OpeningProof, previous *pool.PaymentState, input ContentRequestInput) (*bitfs.SignedContentRequest, error)

// AcceptDelivery 按授权哈希路由到原始 003 后验证整个 004：重算并比较授权哈希、
// 从 OpeningProof 重derive 池绑定、验证卖方对裸 32 字节哈希的签名，
// 再逐项校验 payload 数量/顺序/哈希/归属/长度并重算聚合价格与目标序号，
// 最后本地构造并签署状态交易，但只发送最小 005 凭证（授权哈希 + 买方签名）。
func (workflow *Workflow) AcceptDelivery(ctx context.Context, quote *bitfs.SignedFileQuote, opening *pool.OpeningProof, previous *pool.PaymentState, request *bitfs.SignedContentRequest, delivery *bitfs.SignedContentDelivery, input ContentDeliveryInput) (*VerifiedDelivery, error)

// BuildImmediateClose 从调用方选定的基准状态和调用方选择的目标卖方金额构造
// 未签名最终关闭候选和买方分离签名。SDK 不声称 base 是业务最新状态。
// 把两个值都发送给卖方。
func (workflow *Workflow) BuildImmediateClose(ctx context.Context, opening *pool.OpeningProof, base *pool.PaymentState, targetSellerAmountSat uint64, blockHeight uint32) (*pool.UnsignedPayment, []byte, error)

// CompleteImmediateClose 只验证完整签名的关闭交易对开池证据协议合法；
// 是否匹配业务预期、何时广播都是应用的决定。
func (workflow *Workflow) CompleteImmediateClose(ctx context.Context, opening *pool.OpeningProof, close *pool.SignedPayment) (*pool.SignedPayment, error)

// BuildRefundAfterExpiry 用入口处读取一次的系统 UTC 加调用方提供的高度验证到期，
// 把保存的退款签名合并为可广播交易。SDK 不因存在某笔本地付款状态而拒绝构造。
// 广播是应用的职责；SDK 绝不提交任何东西。
func (workflow *Workflow) BuildRefundAfterExpiry(ctx context.Context, opening *pool.OpeningProof, blockHeight uint32) ([]byte, *pool.PaymentState, error)
```

配套输入类型：

```go
type ContentRequestInput struct {
    ContentHashes    [][]byte // 有序内容哈希批次（1..64 个，不重复）
    DeliveryDeadline bitfs.UnixSeconds
    Seed             []byte // 批次包含任何块时必填
    BlockHeight      uint32 // 仅块高锁定的退款使用
}

type ContentDeliveryInput struct {
    Seed        []byte // 验收包含块的批次时必填
    BlockHeight uint32
}
```

## Seller API

Seller API 没有租约或 pending-request store：`BuildContentDelivery` 返回无锁的 `ContentDeliveryState`，精确记录后续所需协议上下文；应用保存它并在 `AcceptPayment` 时重新传入。

```go
// package seller
type WorkflowConfig struct {
    PrivateKey *ec.PrivateKey // 官方 BSV Go SDK 私钥
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error)

// SellerPresignResult 是 PresignPoolOpening 的复合结果。
type SellerPresignResult struct {
    Response *pool.RefundPresignResponse // 回传买方的 wire 报文
    Opening  *pool.OpeningProof          // 本地预签证据；先保存
}

// PoolFundingAcceptance 是 AcceptPoolFunding 的复合结果。
type PoolFundingAcceptance struct {
    Opening        *pool.OpeningProof // 含 FundingTx 的完整 proof（本地）
    InitialPayment *pool.PaymentState // 初始退款状态（本地）
    FundingTx      []byte             // 通过你自己的节点适配器广播
}

// ContentDeliveryState 记录验证该交付批次的买方 005 凭证所需的协议上下文：
// 费用池 ID、授权哈希、目标序号和绝对累计卖方金额。
// 它不携带 owner/lease/acquire/held/release/expiry 语义——串行化由调用方负责。
type ContentDeliveryState struct {
    RefundTemplateTxID       pool.RefundTemplateTxID
    PaymentAuthorizationHash pool.Hash32
    PaymentSequence          uint32
    SellerAmountAfterSat     uint64
}

// CreateQuote 在入口处读取一次系统 UTC 并以此签名确定性 001 条款。
// 保存返回凭证是应用的职责。
func (workflow *Workflow) CreateQuote(ctx context.Context, draft bitfs.FileQuoteTerms, recommendedFilename string) (*bitfs.SignedFileQuote, error)

// PresignPoolOpening 验证 0201 并返回卖方退款签名与预签形态 proof。
// 发送 Response 之前先保存 Opening。
func (workflow *Workflow) PresignPoolOpening(ctx context.Context, request *pool.RefundPresignRequest) (*SellerPresignResult, error)

// AcceptPoolFunding 用显式提供的预签证据检查 FundingTx 并计算初始退款状态。
// SDK 不提交任何东西：自己广播返回的 FundingTx，再持久化 Opening 与 InitialPayment。
func (workflow *Workflow) AcceptPoolFunding(ctx context.Context, presignProof *pool.OpeningProof, delivery *pool.FundingTxDelivery) (*PoolFundingAcceptance, error)

// BuildContentDelivery 用显式报价/开池/上一状态验证整批 003 授权，
// 逐项校验 payload 后对裸授权哈希签名并编码四元 004。
// 发送交付前先保存返回的 ContentDeliveryState。
func (workflow *Workflow) BuildContentDelivery(ctx context.Context, quote *bitfs.SignedFileQuote, opening *pool.OpeningProof, previous *pool.PaymentState, request *bitfs.SignedContentRequest, input ContentDeliveryInput) (*bitfs.SignedContentDelivery, *ContentDeliveryState, error)

// AcceptPayment 用显式传入的原始签名 003、开池证据、上一状态和保存的
// ContentDeliveryState 验证最小 005 凭证（授权哈希 + 买方交易签名）；
// 通过 BuildPaymentUpdate 本地重建未签名状态交易，对精确重建交易验证买方签名，
// 补上卖方签名并合并完整交易。RawTx 由你自己广播。
func (workflow *Workflow) AcceptPayment(ctx context.Context, opening *pool.OpeningProof, previous *pool.PaymentState, authorization *bitfs.SignedContentRequest, deliveryState *ContentDeliveryState, update *pool.PaymentUpdate, blockHeight uint32) (*pool.SignedPayment, error)

// SignImmediateClose 针对开池证据验证候选结构与协议金额边界，用固定验证器检查
// 买方角色签名，然后添加卖方签名并合并，但不广播。
// 它不判断候选是否匹配任何待处理请求或业务最新金额。
func (workflow *Workflow) SignImmediateClose(ctx context.Context, opening *pool.OpeningProof, unsigned *pool.UnsignedPayment, buyerSig []byte, blockHeight uint32) (*pool.SignedPayment, error)

// BuildArbitrationRequest 验证保存的 003 授权与基准状态，构造被授权候选并签名，
// 打包成 007 证据请求。绝不发送任何东西。
func (workflow *Workflow) BuildArbitrationRequest(ctx context.Context, opening *pool.OpeningProof, authorization *bitfs.SignedContentRequest, base *pool.PaymentState, blockHeight uint32) (*arbitration.ArbitrationRequest, error)

// CompleteArbitratedPayment 用显式证据验证 007 响应哈希与仲裁方签名，合并卖方+仲裁方签名。
// 广播是应用的职责。
func (workflow *Workflow) CompleteArbitratedPayment(ctx context.Context, opening *pool.OpeningProof, previous *pool.PaymentState, request *arbitration.ArbitrationRequest, response *arbitration.ArbitrationResponse, blockHeight uint32) (*pool.SignedPayment, error)
```

## Arbiter API

仲裁方接收完整证据，而不是查询买方或卖方的状态；它不判断内容是否已交付，也不重新计算报价金额。

```go
// package arbitration
type WorkflowConfig struct {
    PrivateKey *ec.PrivateKey // 官方 BSV Go SDK 私钥
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error)

// 应用本地的适配器，不是 SDK 类型。卖家应用可以用 HTTP、队列或本地调用实现该传输。
type ArbiterClient interface {
    SignPayment(ctx context.Context, request *arbitration.ArbitrationRequest) (*arbitration.ArbitrationResponse, error)
}

// SignPayment 检查完整开池证明、最终授权与未签名候选。
// 它只针对这些确切字节返回仲裁方签名，而不是批准状态、金额或数据库 ID。
func (workflow *arbitration.Workflow) SignPayment(
    ctx context.Context,
    request *arbitration.ArbitrationRequest,
) (*arbitration.ArbitrationResponse, error)
```

## 完整业务流程

### 1. 为每个角色创建一套能力

每个 workflow 只需要一把官方 BSV 私钥，没有其他可构造项。

```go
buyerWorkflow, _ := buyer.NewWorkflow(buyer.WorkflowConfig{PrivateKey: buyerKey})
sellerWorkflow, _ := seller.NewWorkflow(seller.WorkflowConfig{PrivateKey: sellerKey})
arbiterWorkflow, _ := arbitration.NewWorkflow(arbitration.WorkflowConfig{PrivateKey: arbiterKey})
```

### 2. 卖家创建报价、买家接受报价

```go
quote, err := sellerWorkflow.CreateQuote(ctx, draftTerms, "file.bin")
save(quote) // 卖方侧持久化

terms, err := buyerWorkflow.AcceptQuote(ctx, quote)
```

### 3. 买卖双方完成资金池开户

```go
// 0201：计算 request + 私有状态；发送 Request 之前先保存 State。
preparation, err := buyerWorkflow.PreparePoolOpening(ctx, pool.OpeningInput{ /* ... */ })
journal.SaveBuyerOpeningState(preparation.State)
send(preparation.Request)

// 0202：验证并预签；发送 Response 之前先保存 Opening。
result, err := sellerWorkflow.PresignPoolOpening(ctx, receivedRequest)
journal.SaveSellerPresignProof(result.Opening)
send(result.Response)

// 0203：按 RefundTemplateTxID 加载保存的状态并显式传入。
state := journal.LoadBuyerOpeningState(response.RefundTemplateTxID)
acceptance, err := buyerWorkflow.AcceptRefundPresign(ctx, state, response)
journal.SaveOpening("buyer", acceptance.Opening)
journal.SaveLatestPayment("buyer", acceptance.InitialPayment)

// 0204：打包已验证 proof 的资金交易。
delivery, err := buyerWorkflow.BuildFundingTxDelivery(ctx, acceptance.Opening)
send(delivery)

// 0205：用保存的预签证据验证资金交付。
opened, err := sellerWorkflow.AcceptPoolFunding(ctx, savedPresignProof, receivedDelivery)
journal.SaveOpening("seller", opened.Opening)
journal.SaveLatestPayment("seller", opened.InitialPayment)
broadcast(opened.FundingTx) // 你的节点适配器声明接受结果
```

### 4. 买家请求内容、卖家交付内容

```go
request, err := buyerWorkflow.BuildContentRequest(ctx, quote, opening, latest, input)
journal.Record(request) // 留痕供 007 使用

delivery, deliveryState, err := sellerWorkflow.BuildContentDelivery(ctx,
    quote, opening, latest, request,
    seller.ContentDeliveryInput{ContentPayloads: contentBatch, Seed: seedBytes})
journal.SaveDeliveryState(deliveryState) // 发送前先保存
send(delivery)
```

### 5. 买家验收交付、卖家接受累计付款

```go
verified, err := buyerWorkflow.AcceptDelivery(ctx, quote, opening, latest, request,
    delivery, buyer.ContentDeliveryInput{Seed: seedBytes})
for _, payload := range verified.Payloads { save(payload) } // 保存是应用的职责
// 最小 005 凭证只携带哈希 + 买方签名；发送前先把原始 003 按授权哈希建立索引。
journal.IndexAuthorization(verified.Update.PaymentAuthorizationHash, request)
send(verified.Update)

authorization := journal.LoadAuthorizationByHash(verified.Update.PaymentAuthorizationHash)
signed, err := sellerWorkflow.AcceptPayment(ctx, opening, latest,
    authorization, savedDeliveryState, verified.Update, blockHeight)
journal.SaveLatestPayment("seller", &signed.State)
broadcast(signed.RawTx)
```

### 6. 付款异常时的仲裁分支

```go
authorization := journal.LoadSentContentRequest(refundTemplateTxID) // 留痕的 003 字节
arbitrationRequest, err := sellerWorkflow.BuildArbitrationRequest(ctx,
    opening, authorization, latest, blockHeight)
response := arbiter.SignPayment(arbitrationRequest)
signed, err := sellerWorkflow.CompleteArbitratedPayment(ctx,
    opening, latest, arbitrationRequest, response, blockHeight)
journal.SaveLatestPayment("seller", &signed.State)
broadcast(signed.RawTx)
```

### 7. 另外两种结局：协商关池与到期退款

```go
unsigned, buyerSig, _ := buyerWorkflow.BuildImmediateClose(ctx, opening, latest, targetSellerAmountSat, blockHeight)
closed, _ := sellerWorkflow.SignImmediateClose(ctx, opening, unsigned, buyerSig, blockHeight)
final, _ := buyerWorkflow.CompleteImmediateClose(ctx, opening, closed)
broadcast(final.RawTx)

raw, state, _ := buyerWorkflow.BuildRefundAfterExpiry(ctx, opening, currentHeight)
broadcast(raw)
```

在每一种结局中，SDK 只负责计算与验证；发送、广播、持久化、重试与对账都是应用动作。
