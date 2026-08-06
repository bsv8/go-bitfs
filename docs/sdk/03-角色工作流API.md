# 03 · 角色工作流 API

返回 [SDK API 框架入口](SDK-API框架设计.md)。

当前实现入口分别是 `buyer.NewClient(buyer.ClientConfig{...})`、`seller.NewService(seller.ServiceConfig{...})` 和 `arbiter.NewService(arbiter.ServiceConfig{...})`。下文保留为角色级调用顺序说明；细节以包中的实际类型和方法为准。

本页描述面向应用开发者的角色门面。它们不持有网络连接：每个方法返回应由应用发送给下一参与方的结构化报文或原始交易。签名、存储、节点等依赖见[外部钩子与数据类型](02-外部钩子与数据类型.md)。

## 买方 API

```go
// package buyer
// Client 只依赖注入的端口。New 必须验证所有必需端口非 nil。
type Client struct { /* 未公开字段 */ }

type Config struct {
    Signer       Signer             // 买方报价/请求/交易签名能力。
    Verifier     SignatureVerifier  // 验证卖方报价与交付签名。
    Clock        Clock               // 校验报价和交付时限。
    Quotes       QuoteStore          // 已验证报价；按请求中的 QuoteTermsHash 找回条款。
    Pools        PoolStore           // 开池证明与已接受付款状态。
    Transactions MultisigPoolPort    // 仅转换参数并调用 MultisigPool canonical API。
    Node         NonFinalPoolNode    // 仅在到期退款或协商关闭提交时使用。
    ContentSink  ContentSink         // 可选；验证 004 后保存内容。
    SeedSource   SeedSource          // 请求 block 时提供已验证 seed；请求 seed 时可为空。
}

func New(config Config) (*Client, error)

// AcceptQuote 验证 001 并保存原始报价。之后 RequestContent 和 AcceptDelivery 才能按哈希取回它。
func (c *buyer.Client) AcceptQuote(
    ctx context.Context,
    quote *bitfs.SignedFileQuote,
) (*bitfs.FileQuoteTerms, error)

// PreparePoolOpening 接受买方钱包准备好的 FundingTx，构造初始远期 RefundTx 并签出买方退款签名。
// 返回的请求是 002 的 PoolRefundPresignRequest，应发送给卖方；此时绝不可广播 FundingTx。
func (c *buyer.Client) PreparePoolOpening(
    ctx context.Context,
    input pool.OpeningInput,
) (*pool.RefundPresignRequest, error)

// AcceptRefundPresign 验证卖方退款签名、保存完整开池证明，并记录初始退款状态。
// 成功意味着买方侧开池完成；卖方尚未必然提交 FundingTx。
func (c *buyer.Client) AcceptRefundPresign(
    ctx context.Context,
    request *pool.RefundPresignRequest,
    response *pool.RefundPresignResponse,
    fundingTx []byte,
) (*pool.Reference, error)

// BuildFundingTxDelivery 在买方保存完整开池证明后，生成可发送给卖方的 002 报文。
func (c *buyer.Client) BuildFundingTxDelivery(
    fundingTx []byte,
) (*pool.FundingTxDelivery, error)

// RequestContent 选择一份已验证报价、一个可用池和一个内容哈希，创建 003。
// 它只读取该池的最后已接受状态。卖方是否存在进行中请求由卖方在处理 003 时判定。
func (c *buyer.Client) RequestContent(
    ctx context.Context,
    input buyer.ContentRequestInput,
) (*bitfs.SignedContentRequest, error)

// AcceptDelivery 验证并可选保存 004 内容，然后按报价价格构造、签署 005。
// 返回的 PaymentUpdate 应发送给卖方；本函数不自行把 update 提交到节点。
func (c *buyer.Client) AcceptDelivery(
    ctx context.Context,
    request *bitfs.SignedContentRequest,
    delivery *bitfs.SignedContentDelivery,
) (*pool.PaymentUpdate, error)

// RefundAfterExpiry 将开池证明中分离保存的双方签名合并到退款交易后提交。
// 若节点已保存更高付款状态，节点会拒绝该旧退款；这不是 SDK 可绕过的失败。
func (c *buyer.Client) RefundAfterExpiry(ctx context.Context, spendTxID Hash32) (Hash32, error)

// BuildImmediateClose 构造空解锁协商关闭交易并返回 Buyer detached signature。
// 交易的 nSequence 与 nLockTime 都为 0xffffffff；它不适用于单方到期退款。
func (c *buyer.Client) BuildImmediateClose(
    ctx context.Context,
    input pool.CloseInput,
) (*pool.UnsignedPayment, []byte, error)

// SubmitImmediateClose 提交卖方已补足签名的最终交易。
// 它只调用 SubmitFinal，不会写入或覆盖非最终交易池状态。
func (c *buyer.Client) SubmitImmediateClose(
    ctx context.Context,
    close *pool.SignedPayment,
) (Hash32, error)
```

`ContentRequestInput` 至少包含：已验证报价、`SpendTxID`、期望的当前 `BasePaymentSequence`、选定仲裁公钥、`ContentRef` 和交付期限。它不接收块索引、报价价格或任意卖方金额。

## 卖方 API

卖方 API 把最危险的“先交付、后付款”窗口封装在一个调用中：先验证 003，再原子加门闩，最后读取内容并签出 004。调用者不得绕过 `DeliverRequestedContent` 而自行交付。

```go
// package seller
type Config struct {
    Signer       Signer             // 卖方报价、交付和交易签名能力。
    Verifier     SignatureVerifier  // 验证买方请求签名。
    Clock        Clock              // 校验报价、请求和交付期限。
    Quotes       QuoteStore         // 按 QuoteTermsHash 找回卖方原始报价。
    Pools        PoolStore          // 开池证明与已接受付款状态。
    Pending      PendingRequestStore // 单请求门闩，必须支持原子 TryAcquire。
    Content      ContentSource      // 按内容哈希读取原始内容。
    Transactions MultisigPoolPort   // 交易验签和 Seller detached signature。
    Node         NonFinalPoolNode   // 提交并确认远期更新。
}

func New(config Config) (*Service, error)

// CreateQuote 创建、签署并保存 001。
// 返回值可经任意调用方网络通道发送给指定买方。
func (s *seller.Service) CreateQuote(
    ctx context.Context,
    draft bitfs.FileQuoteTerms,
    recommendedFilename string,
) (*bitfs.SignedFileQuote, error)

// PresignPoolOpening 验证 002 请求、签署初始退款交易并先保存待激活开池证明。
// 返回响应后，卖方仍没有资金池，不能据此交付内容。
func (s *seller.Service) PresignPoolOpening(
    ctx context.Context,
    request *pool.RefundPresignRequest,
) (*pool.RefundPresignResponse, error)

// AcceptPoolFunding 验证 FundingTx 与已保存证明一致，保存完整证明并提交 FundingTx。
// 只有节点提交成功后，卖方才把池视为可用于 003。
func (s *seller.Service) AcceptPoolFunding(
    ctx context.Context,
    delivery *pool.FundingTxDelivery,
) (*pool.OpeningProof, error)

// DeliverRequestedContent 验证 003、报价、池、公钥、仲裁者、余额和当前序号。
// 它先原子获得该池门闩，之后读取内容、计算哈希、签出 004 并返回。
// 已有门闩时返回 ErrPoolBusy；请求序号不是最新时返回 ErrStalePaymentSequence。
func (s *seller.Service) DeliverRequestedContent(
    ctx context.Context,
    request *bitfs.SignedContentRequest,
) (*bitfs.SignedContentDelivery, error)

// AcceptPayment 验证 005 的原始交易、买方签名、输入、递增 nSequence 和累计金额；
// 卖方签名并提交到非最终交易池。仅节点确认接受后才保存新状态并释放对应门闩。
// 返回值是提交后的状态，不是发送给买方的额外确认报文。
func (s *seller.Service) AcceptPayment(
    ctx context.Context,
    payment *pool.PaymentUpdate,
) (*pool.PaymentState, error)

// SignImmediateClose 验证空解锁关闭交易和 Buyer detached signature，
// 补足 Seller detached signature 并返回可立即提交的完整交易。它不自行广播。
func (s *seller.Service) SignImmediateClose(
    ctx context.Context,
    close *pool.UnsignedPayment,
    buyerSignature []byte,
    signer pool.Signer,
) (*pool.SignedPayment, error)

// BuildArbitrationRequestFromAuthorization 依据最终 003 授权和当前状态构造空解锁候选，并签 Seller。
func (s *seller.Service) BuildArbitrationRequest(
    ctx context.Context,
    proof *pool.OpeningProof,
    authorization *bitfs.SignedContentRequest,
    latest *pool.PaymentState,
) (*arbiter.PaymentSignatureRequest, error)

// SubmitArbitratedPayment 合并仲裁者签名，并通过非最终节点提交同一累计状态。
func (s *seller.Service) SubmitArbitratedPayment(
    ctx context.Context,
    request *arbiter.PaymentSignatureRequest,
    response *arbiter.PaymentSignatureResponse,
) (*pool.PaymentState, error)
```

## 仲裁者 API

仲裁者接收完整证据而非内部查询买卖双方。它不裁定文件是否交付，也不重算报价金额。

```go
// package arbiter
type Config struct {
    Signer       Signer             // 仲裁者 2-of-3 交易签名能力。
    Pool         arbiter.PoolVerifier // 只调用 MultisigPool 验证和 Arbiter 签名。
}

func New(config Config) (*Service, error)

// Client 是卖方通过任意 HTTP、消息队列或本地调用实现的仲裁传输端口。
// 请求和响应本身均为 007 定义的 deterministic CBOR 凭证。
type Client interface {
    SignPayment(ctx context.Context, request *arbiter.PaymentSignatureRequest) (*arbiter.PaymentSignatureResponse, error)
}

// SignPayment 验证 007 证据包中的开池证明、最终授权和空解锁候选交易。
// 校验通过后只返回对该精确交易的仲裁者签名；不返回批准状态、金额或数据库 ID。
func (s *arbiter.Service) SignPayment(
    ctx context.Context,
    request *arbiter.PaymentSignatureRequest,
) (*arbiter.PaymentSignatureResponse, error)
```

## 应用侧最短调用路径

网络由应用自己选择。下面的伪代码展示角色 API 如何衔接，而不是要求 SDK 提供 HTTP 或 RPC：

```go
// 买方先创建 003，经应用网络发送给卖方。
request, err := buyerClient.RequestContent(ctx, requestInput)

// 卖方原子锁定该池、读取内容、生成 004，经应用网络回传。
delivery, err := sellerService.DeliverRequestedContent(ctx, request)

// 买方验收内容并生成 005，经应用网络发送给卖方。
payment, err := buyerClient.AcceptDelivery(ctx, request, delivery)

// 卖方验签、签全并提交 BSV 非最终交易池；没有额外的 005 回执报文。
accepted, err := sellerService.AcceptPayment(ctx, payment)
_ = accepted
```

应用将 `wire.Marshal…` 得到的 `[]byte` 交给任意网络适配器，并在收到时先调用对应 `wire.Unmarshal…`。不得用 JSON 再签名，也不得在传输层新增决定金额或支付序号的字段。
