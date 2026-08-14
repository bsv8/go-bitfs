---
id: external-hooks-and-data-types
title: 02 · 外部钩子与数据类型
---

# 02 · 外部钩子与数据类型

返回 [SDK API 框架入口](sdk-api-framework-design.md)。

调用方把钱包、持久化、内容源和节点能力注入 SDK。SDK 不要求某个数据库或 RPC 服务。

## 签名、时间与内容钩子

```go
// package pool
// Signer 暴露一个角色的公钥和分离签名能力。SDK 永不接收或保存私钥。
type Signer interface {
    PublicKey(ctx context.Context) ([]byte, error)
    Sign(ctx context.Context, payload []byte) ([]byte, error)
}

// package pool
// SignatureVerifier 是费用池适配器使用的通用分离签名验证器。
// 买方和卖方工作流使用下面 bitfs 包中的两个验证函数类型。
type SignatureVerifier interface {
    Verify(pubkey, payload, signature []byte) error
}

// package bitfs
type QuoteTermsSignatureVerifier func(sellerPubkey, termsCBOR, signature []byte) error
type ContentTermsSignatureVerifier func(pubkey, termsCBOR, signature []byte) error

// package buyer
type ContentSink interface {
    SaveVerifiedContent(ctx context.Context, hash bitfs.Hash32, payload []byte) error
}

type SeedSource interface {
    LoadSeed(ctx context.Context, seedHash masterseed.Digest) ([]byte, error)
}

// package seller
// ContentSource 按内容哈希返回 seed 或 block 原始字节；SDK 仍会验证
// 返回内容的哈希和长度。
type ContentSource interface {
    LoadSeed(ctx context.Context, seedHash masterseed.Digest) ([]byte, error)
    LoadBlock(ctx context.Context, blockHash masterseed.Digest) ([]byte, error)
}
```

买方和卖方工作流的 `WorkflowConfig` 使用 `Clock func() time.Time`；当前 API 没有 SDK `Clock` 接口。

## 存储钩子

存储接口按凭证类别拆分。应用可用同一数据库实现它们，也可完全使用文件或内存。

```go
// package buyer; package seller
// 两个角色包分别声明同样的本地 QuoteStore 接口。
type QuoteStore interface {
    SaveQuote(ctx context.Context, quote *bitfs.SignedFileQuote) error
    LoadQuote(ctx context.Context, termsHash bitfs.Hash32) (*bitfs.SignedFileQuote, error)
}

// package pool
// PoolStore 保存完整开池证明、节点接受的付款状态、健康/重协调状态，
// 以及卖方按 funding ID 查询开池证明所需的能力。
type PoolStore interface {
    OpeningProofStore
    LoadOpeningProofByFundingTxID(context.Context, Hash32) (*OpeningProof, error)
    SaveAcceptedPayment(context.Context, *PaymentState) error
    LoadAcceptedPayment(context.Context, Hash32) (*PaymentState, error)
    EnsurePoolHealthy(context.Context, Hash32) error
    MarkExternalStateUncertain(context.Context, Hash32, Hash32) error
    ReconcileExternalState(context.Context, Hash32, *PaymentState) error
}

// package pool
// PendingRequestStore 原子管理卖方交付门闩。
type PendingRequestStore interface {
    TryAcquire(context.Context, PendingRequest) (PendingAcquireResult, error)
    Load(context.Context, Hash32) (*PendingRequest, error)
    Release(context.Context, Hash32, Hash32) error
}
```

`bitfs.FileQuoteStore` 实现角色本地的报价存储接口。`pool.MemoryStore` 和
`pool.FileStore` 实现当前支持的 `pool.PoolStore` 与
`pool.PendingRequestStore`。

## BSV 节点与交易钩子

普通广播和非最终交易更新语义不同，必须使用不同方法，避免调用方误把 HTTP 成功当作池状态已推进。

```go
// package pool
type BuyerPoolPort interface {
    TransactionID([]byte) (Hash32, error)
    BuildRefundPresignRequest(context.Context, OpeningInput, Signer) (*RefundPresignRequest, error)
    BuildRefundSubmission(*OpeningProof) ([]byte, error)
    VerifyRefundExpired(*OpeningProof, time.Time) error
    VerifyOpening(*OpeningProof) error
    ParsePaymentState(context.Context, []byte, *OpeningProof) (*PaymentState, error)
    ParseUnsignedPayment(context.Context, []byte, *OpeningProof) (*UnsignedPayment, error)
    VerifyAcceptedPayment(*PaymentState, *OpeningProof) error
    VerifyBuyerPayment(*UnsignedPayment, []byte, *OpeningProof) error
    VerifyCompletedFinalPayment(*SignedPayment, *OpeningProof) error
    CheckPaymentCapacity(context.Context, PaymentUpdateInput) error
    BuildPaymentUpdate(context.Context, PaymentUpdateInput) (*UnsignedPayment, error)
    SignBuyerPayment(context.Context, *UnsignedPayment, Signer) ([]byte, error)
    BuildImmediateClose(context.Context, CloseInput) (*UnsignedPayment, []byte, error)
}

// package pool
type SellerPoolPort interface {
    TransactionID([]byte) (Hash32, error)
    FundingTxID([]byte) (Hash32, error)
    BuildRefundSubmission(*OpeningProof) ([]byte, error)
    VerifyOpening(*OpeningProof) error
    ParsePaymentState(context.Context, []byte, *OpeningProof) (*PaymentState, error)
    ParseUnsignedPayment(context.Context, []byte, *OpeningProof) (*UnsignedPayment, error)
    VerifyAcceptedPayment(*PaymentState, *OpeningProof) error
    VerifyArbitratedPayment(*PaymentState, *OpeningProof) error
    VerifyBuyerPayment(*UnsignedPayment, []byte, *OpeningProof) error
    VerifySellerPayment(*UnsignedPayment, []byte, *OpeningProof) error
    CheckPaymentCapacity(context.Context, PaymentUpdateInput) error
    BuildPaymentUpdate(context.Context, PaymentUpdateInput) (*UnsignedPayment, error)
    SignSellerArbitrationCandidate(context.Context, *UnsignedPayment, Signer) ([]byte, error)
    SignSellerPayment(context.Context, *UnsignedPayment, Signer) ([]byte, error)
    MergeBuyerSellerPayment(*UnsignedPayment, []byte, []byte) (*SignedPayment, error)
    MergeSellerArbiterPayment(*UnsignedPayment, []byte, []byte) (*SignedPayment, error)
    SignImmediateClose(context.Context, *UnsignedPayment, []byte, Signer) (*SignedPayment, error)
}

// package arbitration
type PoolPort interface {
    VerifyOpening(*pool.OpeningProof) error
    VerifyArbitrationCandidate(context.Context, []byte, *pool.OpeningProof, *bitfs.ContentRequestTerms, []byte) (*pool.UnsignedPayment, error)
    SignArbitrationCandidate(context.Context, []byte, *pool.OpeningProof, pool.Signer) ([]byte, error)
}

// package pool
type NonFinalPoolNode interface {
    SubmitUpdate(context.Context, []byte) (*UpdateAcceptance, error)
    SubmitFinal(context.Context, []byte) (Hash32, error)
}
```

具体 `pool.MultisigPoolEngine` 适配器使用角色专属的 `PrivateKeyProvider`
计算交易 sighash；它和工作流凭证用的通用 `Signer` 是分开的。

代码提供的 `pool.VerifiedNonFinalPoolNode` 是节点适配层：它在调用外部后端前重新解析并验证非最终交易、最终双签交易或到期退款，在后端返回后校验交易 ID、`SpendTxID` 和序号完全一致。

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
    QuoteTermsHash        bitfs.Hash32     // 已经 AcceptQuote 的报价条款哈希。
    Pool                  pool.Reference   // 要使用的一个有效费用池及当前序号。
    SelectedArbiterPubKey []byte           // 必须属于报价允许列表，且等于开池仲裁公钥。
    Content               bitfs.ContentRef // Seed 或 Block 加其内容哈希。
    ContentSize           uint64           // 用于计价的预期内容大小。
    DeliveryDeadline      bitfs.UnixSeconds // 买方接受的最晚交付时刻。
}

// package pool
// OpeningInput 是买方钱包已经准备好资金交易后交给费用池层的输入。
// FundingTx 必须是尚未公开的、买方已签名原始交易；PoolOutputIndex 指向其中的 2-of-3 输出。
type OpeningInput struct {
    FundingTx            []byte
    PoolOutputIndex      uint32
    ExpiryLockTime       uint32
    MinerFeeRateSatPerKB uint64
    SellerPubKey         []byte
    ArbiterPubKey        []byte
}

// PaymentUpdateInput 是 pool 层的低层输入，适用于非 BitFS 的通用费用池调用。
// buyer.Workflow 不直接暴露 SellerAmountAfter；它会从已验证的 001、003、004 自动计算。
type PaymentUpdateInput struct {
    Opening              *OpeningProof // 完整开池证明，而非数据库 ID。
    Previous             *PaymentState // 已接受的最新状态；首笔付款可表示初始退款状态。
    PaymentSequenceAfter uint32        // 必须大于 Previous 的 nSequence，且小于 0xffffffff。
    SellerAmountAfterSat uint64        // 卖方累计金额，不是本次增量。
}

// CloseInput 仅用于双方协商立即关闭。
// SellerAmountAfterSat 通常等于最后接受付款状态中的卖方累计金额；不得据此重新定价。
type CloseInput struct {
    Opening              *OpeningProof
    Latest               *PaymentState
    SellerAmountAfterSat uint64
}
```
