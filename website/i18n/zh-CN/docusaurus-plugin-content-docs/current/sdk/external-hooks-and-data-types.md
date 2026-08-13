---
id: external-hooks-and-data-types
title: 02 · 外部钩子与数据类型
---

# 02 · 外部钩子与数据类型

返回 [SDK API 框架入口](sdk-api-framework-design.md)。

调用方把钱包、持久化、内容源和节点能力注入 SDK。SDK 不要求某个数据库或 RPC 服务。

## 签名、时间与内容钩子

```go
// Signer 使用调用方托管的私钥签出精确 bytes。
// SDK 永不接收或保存私钥。
type Signer interface {
    PublicKey(ctx context.Context) ([]byte, error)
    Sign(ctx context.Context, payload []byte) ([]byte, error)
}

// SignatureVerifier 验证某个公钥对精确 payload 的签名。
// 001、003、004 使用它；005 使用 MultisigPoolPort 的交易签名校验。
type SignatureVerifier interface {
    Verify(pubkey, payload, signature []byte) error
}

// Clock 使到期校验可测试，且禁止工作流直接调用 time.Now。
type Clock interface {
    NowUnix() UnixSeconds
}

// ContentSource 只由卖方实现。它按内容哈希返回 seed 或块的原始字节。
// 返回的内容仍会由 SDK 再计算哈希和长度。
type ContentSource interface {
    LoadContent(ctx context.Context, hash Hash32) ([]byte, error)
}

// SeedSource 只由买方实现。请求 block 时提供已验证的 seed，SDK 会校验
// seed_hash 以及 block hash 的成员关系。
type SeedSource interface {
    LoadSeed(ctx context.Context, seedHash Hash32) ([]byte, error)
}

// ContentSink 是买方可选的落盘钩子。SDK 在验证 004 后才调用它。
type ContentSink interface {
    SaveVerifiedContent(ctx context.Context, hash Hash32, payload []byte) error
}
```

## 存储钩子

存储接口按凭证类别拆分。应用可用同一数据库实现它们，也可完全使用文件或内存。

```go
// QuoteStore 保存双方已经验证的 001；用于按 QuoteTermsHash 找回原始凭证。
// 卖方用它验证 003，买方用它在验收 004 和构造 005 时取得价格与卖方公钥。
type QuoteStore interface {
    SaveQuote(ctx context.Context, quote *bitfs.SignedFileQuote) error
    LoadQuote(ctx context.Context, termsHash Hash32) (*bitfs.SignedFileQuote, error)
}

// PoolStore 保存完整开池证明和最后被节点接受的付款状态。
// SpendTxID 是初始远期花费交易 ID，是稳定锚点，不是每次 update 的交易 ID。
type PoolStore interface {
    SaveOpeningProof(ctx context.Context, proof *pool.OpeningProof) error
    LoadOpeningProof(ctx context.Context, spendTxID Hash32) (*pool.OpeningProof, error)
    SaveAcceptedPayment(ctx context.Context, payment *pool.PaymentState) error
    LoadAcceptedPayment(ctx context.Context, spendTxID Hash32) (*pool.PaymentState, error)
}

// package pool
// PendingRequest 是卖方单请求门闩的持久化内容。它是交付保护状态，不是付款真值。
// ExpectedSellerAmountSat 是在验证 001、003、内容成员关系后计算出的本次
// 卖方累计金额增量；AcceptPayment 必须要求交易卖方金额恰好增加该值。
type PendingRequest struct {
    SpendTxID               Hash32 // 稳定的初始远期花费交易 ID。
    BasePaymentSequence     uint32 // 卖方接受该请求时的最新 nSequence。
    ContentRequestHash      Hash32 // 003 条款哈希；005 必须引用同一请求。
    ExpectedSellerAmountSat uint64 // 已验证内容对应的精确累计金额增量。
}

// PendingRequestStore 必须具备“检查当前状态并写入门闩”的原子语义；
// TryAcquire 返回 PendingAcquired、PendingAlreadyHeld 或 PendingConflict。
// 后两者都必须阻止再次进入交付副作用；该端口引用 pool.PendingRequest，
// 避免依赖 seller 包而形成循环。
type PendingRequestStore interface {
    TryAcquire(ctx context.Context, pending pool.PendingRequest) (result pool.PendingAcquireResult, err error)
    Load(ctx context.Context, spendTxID Hash32) (*pool.PendingRequest, error)
    Release(ctx context.Context, spendTxID Hash32, requestHash Hash32) error
}
```

代码提供的 `bitfs.FileQuoteStore` 使用 advisory lock 加原子快照，可在 Unix 上安全串行化遵守同一锁文件约定的多进程读写；需要更强事务、索引或集群锁语义时仍应替换为数据库实现。它按规范化的 `FileQuoteTermsHash` 持久化完整签名报价。

代码提供的 `pool.MemoryStore` 只适合测试和单进程临时运行；`pool.FileStore` 使用 advisory lock、每次操作前重载和原子快照保存开池证明、最新付款状态和 `ExpectedSellerAmountSat`，可在 Unix 上串行化遵守同一锁文件约定的多进程读写。需要更强事务、索引或集群锁语义时仍应注入数据库实现。

## BSV 节点与交易钩子

普通广播和非最终交易更新语义不同，必须使用不同方法，避免调用方误把 HTTP 成功当作池状态已推进。

```go
// MultisigPoolPort 只做业务对象到 MultisigPool canonical API 的转换和编排。
// 它不访问网络，也不保存状态。
type MultisigPoolPort interface {
    TransactionID(rawTx []byte) (Hash32, error)
    VerifyOpening(proof *pool.OpeningProof) error
    ParseFinalPaymentState(ctx context.Context, rawTx []byte, proof *pool.OpeningProof) (*pool.PaymentState, error)
    VerifyAcceptedPayment(state *pool.PaymentState, proof *pool.OpeningProof) error
    BuildRefundSubmission(proof *pool.OpeningProof) ([]byte, error)
    BuildPaymentUpdate(ctx context.Context, input pool.PaymentUpdateInput) (*pool.UnsignedPayment, error)
    SignBuyerPayment(ctx context.Context, payment *pool.UnsignedPayment, buyer Signer) ([]byte, error)
    VerifyBuyerPayment(payment *pool.UnsignedPayment, signature []byte, proof *pool.OpeningProof) error
    SignSellerPayment(ctx context.Context, payment *pool.UnsignedPayment, seller Signer) ([]byte, error)
    MergeBuyerSellerPayment(payment *pool.UnsignedPayment, buyerSignature, sellerSignature []byte) (*pool.SignedPayment, error)
    VerifyArbitratedPayment(state *pool.PaymentState, proof *pool.OpeningProof) error
    MergeSellerArbiterPayment(payment *pool.UnsignedPayment, sellerSignature, arbiterSignature []byte) (*pool.SignedPayment, error)
    BuildImmediateClose(ctx context.Context, input pool.CloseInput) (*pool.UnsignedPayment, []byte, error)
    VerifyFinalPayment(state *pool.PaymentState, proof *pool.OpeningProof) error
    VerifyCompletedFinalPayment(payment *pool.SignedPayment, proof *pool.OpeningProof) error
}

// NonFinalPoolNode 是 BSV 非最终交易池的专用端口。
// SubmitUpdate 必须只在节点确认“同一输入、更高 nSequence”的 update 已保存后返回 nil。
type NonFinalPoolNode interface {
    SubmitUpdate(ctx context.Context, rawSignedTx []byte) (*pool.UpdateAcceptance, error)
    SubmitFinal(ctx context.Context, rawSignedTx []byte) (txid Hash32, err error)
}
```

代码提供的 `pool.VerifiedNonFinalPoolNode` 是节点适配层：它在调用外部后端前重新解析并验证非最终交易、最终双签交易或到期退款，在后端返回后校验交易 ID、`SpendTxID` 和序号完全一致。具体 BSV RPC/SDK 通过 `pool.NonFinalPoolBackend` 注入；仓库不假设某个节点厂商的 RPC 路径或响应格式。

`UpdateAcceptance` 至少包含被接受交易的 ID、`SpendTxID` 锚点和已接受的 `nSequence`。若节点只提供“已收到”而不提供状态接受保证，不得实现此接口。

## 关键输入类型

工作流 API 不让应用重复填写已经能从凭证推导的字段。以下类型是少数必须由调用方明确选择或提供的输入。

```go
// package pool
// Reference 是 003 选择费用池时使用的稳定引用。
// SpendTxID 永远是初始远期花费交易 ID，不能填某次 update 的交易 ID。
type Reference struct {
    SpendTxID           Hash32
    BasePaymentSequence uint32 // 买方看到的该池当前最新 nSequence。
}

// package buyer
// ContentRequestInput 是买方创建 003 时的唯一业务选择。
// 它不包含价格、块索引、卖方金额或文件名；这些均从已保存报价和 seed 推导。
type ContentRequestInput struct {
    QuoteTermsHash        Hash32           // 已经 AcceptQuote 的报价条款哈希。
    Pool                  pool.Reference   // 要使用的一个有效费用池及当前序号。
    SelectedArbiterPubKey []byte           // 必须属于报价允许列表，且等于开池仲裁公钥。
    Content               bitfs.ContentRef // Seed 或 Block 加其内容哈希。
    DeliveryDeadline      UnixSeconds      // 买方接受的最晚交付时刻。
}

// package pool
// OpeningInput 是买方钱包已经准备好资金交易后交给费用池层的输入。
// FundingTx 必须是尚未公开的、买方已签名原始交易；PoolOutputIndex 指向其中的 2-of-3 输出。
type OpeningInput struct {
    FundingTx       []byte // 买方钱包构造并签名的原始资金交易。
    PoolOutputIndex uint32 // FundingTx 中唯一 2-of-3 池输出的位置。
    ExpiryLockTime  uint32 // <500000000 为区块高度锁，>=500000000 为 Unix 时间锁；高度锁必须注入 BlockHeight。
    MinerFeeRateSatPerKB uint64 // 统一费用池固定的整数矿工费率；后续状态不得改价。
    SellerPubKey    []byte // 卖方公钥。
    ArbiterPubKey   []byte // 本池唯一仲裁公钥。
}

// PaymentUpdateInput 是 pool 层的低层输入，适用于非 BitFS 的通用费用池调用。
// buyer.Workflow 不直接暴露 SellerAmountAfter；它会从已验证的 001、003、004 自动计算。
type PaymentUpdateInput struct {
    Opening              *OpeningProof // 完整开池证明，而非数据库 ID。
    Previous             *PaymentState // 已接受的最新状态；首笔付款可表示初始退款状态。
    PaymentSequenceAfter uint32        // 必须大于 Previous 的 nSequence，且小于 0xffffffff。
    SellerAmountAfterSat uint64        // 卖方累计金额，不是本次增量。
    MinerFeeRateSatPerKB uint64       // 开池固定的整数矿工费率。
}

// CloseInput 仅用于双方协商立即关闭。
// SellerAmountAfterSat 通常等于最后接受付款状态中的卖方累计金额；不得据此重新定价。
type CloseInput struct {
    Opening              *OpeningProof
    Latest               *PaymentState
    SellerAmountAfterSat uint64
    MinerFeeRateSatPerKB uint64
}
```
