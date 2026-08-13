---
id: protocol-foundations-and-cbor
title: 01 · 协议基础与 CBOR
---

# 01 · 协议基础与 CBOR

返回 [SDK API 框架入口](sdk-api-framework-design.md)。

当前代码已落地本页的核心边界：`bitfs`、`pool`、`buyer.Workflow`、`seller.Workflow`、`arbitration.Workflow` 和 `wire` 均可直接使用；本文中的伪代码用于说明职责，不替代 Go 包的实际签名。

## 设计目标

使用者应能沿业务顺序完成一次购买，而不需要理解 CBOR 数组位置、交易签名拼接或非最终交易池细节：

```text
卖方签报价
  -> 买方开费用池
  -> 买方请求 seed / block
  -> 卖方交付内容
  -> 买方签累计支付
  -> 卖方推进远期交易
  -> 到期退款 / 协商关闭 / 卖方仲裁
```

## 包边界

新 API 采用“纯协议核心 + 角色工作流 + 外部端口”的三层结构。旧 `HashGetTicket`、`proposal_id`、会话池 API 仅作为历史文档保留，不属于当前实现或新入口。

```text
bitfs/       001、003、004 的凭证、CBOR、签名和内容校验
pool/        002、005、006 的通用 2-of-3 费用池与 BSV 交易校验
buyer/       买方工作流门面，只产生下一步应发送的凭证或交易
seller/      卖方工作流门面，负责交付门闩、验收并推进远期交易
arbitration/     007 仲裁证据校验和交易签名门面
wire/        所有新协议报文的 deterministic CBOR 编码、严格解码和类型分派
transport/   可选的调用方适配层；SDK 核心不依赖它
```

`pool/` 不得引用报价、seed、文件块或 BitFS 内容类型；`bitfs/` 不得自行提交链上交易。`wire/` 不签名、不访问存储、不提交交易，只处理精确 CBOR bytes。`buyer/`、`seller/` 只编排上述领域。

## 通用约定

```go
// Hash32 表示 SHA-256 结果。公开 API 不接受长度不明的“哈希字符串”。
type Hash32 [32]byte

// UnixSeconds 使用 UTC Unix 秒，与 001、003 的 CBOR 字段一致。
type UnixSeconds int64
```

- 公钥、签名、原始交易和 CBOR 均使用 `[]byte`；实现必须复制外部传入的可变切片。
- 每个 `wire.Unmarshal…` 函数只接受 deterministic CBOR；解析成功不等于业务校验成功。
- 每个 `Verify…` 函数均验证精确原始字节及签名；不得“重新编码后再验”。
- 所有会产生外部副作用的函数接受 `context.Context`。

### 错误模型

调用者应能根据错误类别决定重试、拒绝还是提示用户。框架统一返回可用 `errors.Is` 判断的哨兵错误，并在需要时包装底层原因：

```go
var (
    ErrInvalidEvidence      error // CBOR、哈希、签名或交易内容不自洽。
    ErrQuoteExpired         error // 001 报价已到期。
    ErrPoolBusy             error // 卖方已有一笔未完成交付，不能再用同一池交付。
    ErrStalePaymentSequence error // 请求或付款所依据的池状态不是当前状态。
    ErrInsufficientBalance  error // 池余额不足以支付内容及交易费。
    ErrNonFinalRejected     error // BSV 非最终交易池拒绝本次 update。
    ErrFinalRejected         error // BSV 节点拒绝最终交易。
    ErrNotExpired            error // 到期退款尚未达到时间锁。
    ErrContentNotInSeed      error // block 未被报价对应 seed 提交。
)
```

`ErrPoolBusy` 和 `ErrStalePaymentSequence` 是可预期的业务结果，不应被包装为“内部错误”。

## 统一 CBOR 报文 API

CBOR 的打包与解包属于 SDK，不属于 HTTP、WebSocket、队列或应用代码。应用不得直接使用第三方 CBOR 库重编码协议对象；也不得把结构体 JSON 化后再自行签名。

`wire` 不给既有 001–007 报文再套一层全局 envelope：那会改变已经确定的签名和数组结构。报文类型由通信路由、接口路径或调用方显式传入；CBOR 本体始终是各规范定义的原始 deterministic CBOR bytes。

```go
// package wire
// Kind 是传输层已知的报文类别，用于统一分派；它不进入 001–007 的已签名 CBOR 本体。
type Kind uint16

const (
    Quote                     Kind = 1 // 001 SignedFileQuote。
    PoolRefundPresignRequest  Kind = 2 // 002 买方 -> 卖方。
    PoolRefundPresignResponse Kind = 3 // 002 卖方 -> 买方。
    PoolFundingTxDelivery     Kind = 4 // 002 买方 -> 卖方。
    ContentRequest            Kind = 5 // 003 买方 -> 卖方。
    ContentDelivery           Kind = 6 // 004 卖方 -> 买方。
    CumulativePayment         Kind = 7 // 005 买方 -> 卖方。
    ArbitrationRequest        Kind = 8 // 007 卖方 -> 仲裁者。
    ArbitrationResponse       Kind = 9 // 007 仲裁者 -> 卖方。
)

// Packet 是应用可以直接投递的统一报文表示。
// Kind 应由外层路由携带；CBOR 必须原样发送、原样保存，禁止二次编码。
type Packet struct {
    Kind Kind
    CBOR []byte
}

// Marshal 按 Kind 对精确类型进行 deterministic CBOR 编码。
// Kind 与 message 类型不匹配、对象不满足字段长度约束或编码非确定时返回 ErrInvalidEvidence。
// 例如：Marshal(ContentRequest, request)。
func Marshal(kind Kind, message any) (Packet, error)

// Unmarshal 按调用方已知 Kind 严格解码。它拒绝非 canonical CBOR、未知版本、数组长度不符和 Kind/结构不匹配。
// 返回对象的具体类型由 Kind 决定，例如 ContentRequest 返回 *bitfs.SignedContentRequest。
// 调用者在继续业务流程前仍必须调用相应 Verify 函数。
func Unmarshal(kind Kind, rawCBOR []byte) (any, error)

// Typed helpers 是多数应用应使用的 API；它们避免 any 和类型断言。
func MarshalQuote(message *bitfs.SignedFileQuote) ([]byte, error)
func UnmarshalQuote(rawCBOR []byte) (*bitfs.SignedFileQuote, error)
func MarshalPoolRefundPresignRequest(message *pool.RefundPresignRequest) ([]byte, error)
func UnmarshalPoolRefundPresignRequest(rawCBOR []byte) (*pool.RefundPresignRequest, error)
func MarshalPoolRefundPresignResponse(message *pool.RefundPresignResponse) ([]byte, error)
func UnmarshalPoolRefundPresignResponse(rawCBOR []byte) (*pool.RefundPresignResponse, error)
func MarshalPoolFundingTxDelivery(message *pool.FundingTxDelivery) ([]byte, error)
func UnmarshalPoolFundingTxDelivery(rawCBOR []byte) (*pool.FundingTxDelivery, error)
func MarshalContentRequest(message *bitfs.SignedContentRequest) ([]byte, error)
func UnmarshalContentRequest(rawCBOR []byte) (*bitfs.SignedContentRequest, error)
func MarshalContentDelivery(message *bitfs.SignedContentDelivery) ([]byte, error)
func UnmarshalContentDelivery(rawCBOR []byte) (*bitfs.SignedContentDelivery, error)
func MarshalPaymentUpdate(message *pool.PaymentUpdate) ([]byte, error)
func UnmarshalPaymentUpdate(rawCBOR []byte) (*pool.PaymentUpdate, error)
func MarshalArbitrationRequest(message *arbitration.ArbitrationRequest) ([]byte, error)
func UnmarshalArbitrationRequest(rawCBOR []byte) (*arbitration.ArbitrationRequest, error)
func MarshalArbitrationResponse(message *arbitration.ArbitrationResponse) ([]byte, error)
func UnmarshalArbitrationResponse(rawCBOR []byte) (*arbitration.ArbitrationResponse, error)
```

006 没有新的应用层关闭报文，关闭行为使用 002/005 中已保存的原始交易，不应虚构新的 CBOR `CloseRequest`。

`Unmarshal` 只解决“字节是否是此类规范 CBOR”；随后由 `VerifyQuote`、`VerifyContentDelivery`、`MultisigPoolPort.Verify…` 等校验签名、报价有效期、费用池输入和金额。解码器绝不能把“成功解码”暴露为“已验证”或“已付款”。

## 纯协议 API

这些函数没有存储、网络和时间以外的副作用，适合钱包、服务端、CLI 和测试直接使用。

```go
// CreateQuote 对 FileQuoteTerms 的 deterministic CBOR 进行签名，生成 001 报价凭证。
// draft 包含 seed 哈希、种子价、块价、文件大小、买方公钥、失效时间和可选仲裁公钥。
// recommendedFilename 仅为展示信息，不进入签名条款。
func CreateQuote(
    ctx context.Context,
    draft bitfs.FileQuoteTerms,
    recommendedFilename string,
    seller Signer,
) (*bitfs.SignedFileQuote, error)

// VerifyQuote 验证卖方签名、字段约束和 expires_at；成功时返回已解析的不可变条款。
func VerifyQuote(
    quote *bitfs.SignedFileQuote,
    now UnixSeconds,
    verifier SignatureVerifier,
) (*bitfs.FileQuoteTerms, error)

// CreateContentRequest 构造并由买方签署 003。
// poolRef 指定 SpendTxID 与当前 BasePaymentSequence；content 只接受 Seed 或 Block + 内容哈希。
// 它不锁池、不下载内容、不创建付款交易。
func CreateContentRequest(
    ctx context.Context,
    quote *bitfs.SignedFileQuote,
    poolRef pool.Reference,
    selectedArbiterPubKey []byte,
    content bitfs.ContentRef,
    deliveryDeadline UnixSeconds,
    buyer Signer,
) (*bitfs.SignedContentRequest, error)

// VerifyContentDelivery 验证 004 引用的 003、卖方签名、内容哈希和实际长度。
// 可选 sink 非 nil 时，仅在全部验证成功后保存内容。
func VerifyContentDelivery(
    ctx context.Context,
    request *bitfs.SignedContentRequest,
    delivery *bitfs.SignedContentDelivery,
    quote *bitfs.SignedFileQuote,
    now UnixSeconds,
    verifier SignatureVerifier,
    sink ContentSink,
) ([]byte, error)
```
