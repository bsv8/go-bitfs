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
seller/      卖方工作流门面，验收交付并推进远期交易；交付上下文的串行化由调用方应用负责
arbitration/     007 仲裁证据校验和交易签名门面
wire/        所有新协议报文的 deterministic CBOR 编码、严格解码和类型分派
transport/   可选的调用方适配层；SDK 核心不依赖它
```

`pool/` 不得引用报价、seed、文件块或 BitFS 内容类型；`bitfs/` 不得自行提交链上交易。`wire/` 不签名、不访问存储、不提交交易，只处理精确 CBOR bytes。`buyer/`、`seller/` 只编排上述领域。

## 通用约定

```go
// package bitfs；package pool
// 两个包都使用固定 32 字节的 SHA-256 引用，但属于各自包的 API 类型。
type Hash32 [32]byte

// package bitfs
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
    ErrStalePaymentSequence error // 请求或付款所依据的池状态不是当前状态。
    ErrInsufficientBalance  error // 池余额不足以支付内容及交易费。
    ErrNotExpired            error // 到期退款尚未达到时间锁。
    ErrContentNotInSeed      error // block 未被报价对应 seed 提交。
)
```

`ErrStalePaymentSequence` 是可预期的业务结果，不应被包装为“内部错误”。

## 统一 CBOR 报文 API

CBOR 的打包与解包属于 SDK，不属于 HTTP、WebSocket、队列或应用代码。应用不得直接使用第三方 CBOR 库重编码协议对象；也不得把结构体 JSON 化后再自行签名。

`wire` 不给既有 001–007 报文再套一层全局 envelope：那会改变已经确定的签名和数组结构。报文类型由通信路由、接口路径或调用方显式传入；CBOR 本体始终是各规范定义的原始 deterministic CBOR bytes。

```go
// package wire
// Kind 是传输层已知的报文类别，用于统一分派；它不进入 001–007 的已签名 CBOR 本体，
// 也绝不标识费用池实例：定义 RefundTemplateTxID 的报文会在 CBOR 文档中携带它；0201
// 预签请求从 RefundTx 推导该值，不包含单独的 hash 字段。
type Kind uint16

const (
    // Quote 是签名文件报价。
    // Direction: 卖方 -> 买方。
    Quote Kind = 1

    // PoolRefundPresignRequest 请求卖方签署退款交易。
    // Direction: 买方 -> 卖方。
    PoolRefundPresignRequest Kind = 2

    // PoolRefundPresignResponse 携带卖方的退款交易签名。
    // Direction: 卖方 -> 买方。
    PoolRefundPresignResponse Kind = 3

    // PoolFundingTxDelivery 携带已签名的资金交易。
    // Direction: 买方 -> 卖方。
    PoolFundingTxDelivery Kind = 4

    // ContentRequest 携带签名内容请求和付款授权。
    // Direction: 买方 -> 卖方。
    ContentRequest Kind = 5

    // ContentDelivery 携带签名内容交付。
    // Direction: 卖方 -> 买方。
    ContentDelivery Kind = 6

    // CumulativePayment 携带累计付款更新。
    // Direction: 买方 -> 卖方。
    CumulativePayment Kind = 7

    // ArbitrationRequest 携带仲裁证据。
    // Direction: 卖方 -> 仲裁者。
    ArbitrationRequest Kind = 8

    // ArbitrationResponse 携带仲裁者的签名结果。
    // Direction: 仲裁者 -> 卖方。
    ArbitrationResponse Kind = 9
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

`Unmarshal` 只解决“字节是否是此类规范 CBOR”；随后由角色工作流使用 SDK 固定验证器校验签名、报价有效期、费用池输入和金额——不存在需要调用方配置的签名验证回调。解码器绝不能把“成功解码”暴露为“已验证”或“已付款”。

所有协议身份公钥都必须编码为合法的 33 字节压缩 secp256k1 公钥。固定验证
层会在它们进入签名的 001/003/004 条款或 002 费用池证据前拒绝 65 字节未压缩公钥。

## 纯协议 API

这些函数没有存储或网络副作用，适合钱包、服务端、CLI 和测试直接使用。签名直接使用调用方解析的官方 BSV 私钥（`github.com/bsv-blockchain/go-sdk/primitives/ec` 的 `ec.PrivateKey`；TypeScript 使用 `@bsv/sdk` 原生 `PrivateKey`）。不存在 signer 或 verifier 回调。

所有凭证的签名路径固定且一致：被签字节（规范条款 CBOR，或 004 的裸 32 字节授权哈希）用 SHA-256 哈希一次，官方私钥对这份已算好的摘要签名，low-S DER 结果在返回前由固定内部验证器对照该角色派生公钥复验。Go 侧 `(*ec.PrivateKey).Sign` 接收已算好的 digest，而 TS 侧 `PrivateKey.sign(message)` 会自行哈希——跨语言向量必须避免双重哈希。交易签名使用固定的 MultisigPool sighash（`ForkID|All`），绝不做二次哈希。

```go
// package bitfs
// NewSignedFileQuote 验证报价条款，编码规范 TermsCBOR，通过固定的一次
// SHA-256 消息签名路径用卖方官方 BSV 私钥为这些精确字节签名，并在返回
// 001 凭证前用派生公钥固定复验签名。
func NewSignedFileQuote(
    terms *FileQuoteTerms,
    sellerKey *ec.PrivateKey,
    recommendedFilename string,
) (*SignedFileQuote, error)

// VerifySignedFileQuote 在入口处读取一次系统 UTC 并使用 SDK 固定验证器，
// 验证卖方签名、字段约束和报价有效期。
// 不存在 now 参数，也没有可传入的 verifier 参数。
func VerifySignedFileQuote(quote *SignedFileQuote) (*FileQuoteTerms, error)

// NewSignedContentRequest 确定性编码 003 条款，并通过同一条固定的一次
// SHA-256 消息签名路径用买方官方 BSV 私钥为这些精确字节签名。
func NewSignedContentRequest(terms *ContentRequestTerms, buyerKey *ec.PrivateKey) (*SignedContentRequest, error)

// VerifySignedContentRequest 在入口处读取一次系统 UTC 并使用 SDK 固定验证器，
// 验证报价绑定、资金池参与方、买方对精确条款字节的签名、报价过期和交付期限。
// VerifySignedContentRequestForOpening 为已携带 OpeningProof 的证据（007）
// 只验证池绑定与买方签名。VerifySignedContentRequestWithSeed 额外证明每个
// 请求的块哈希都存在于绑定报价的 seed 中。
func VerifySignedContentRequest(
    request *SignedContentRequest,
    quote *SignedFileQuote,
    opening PoolOpeningEvidence,
) (*ContentRequestTerms, error)

// NewSignedContentDelivery 通过固定消息路径用卖方官方 BSV 私钥对精确 32 字节
// 的付款授权哈希签名，并附上规范编码的有序 payload 批次。payload 通过所引用
// 003 提交的哈希间接绑定。
func NewSignedContentDelivery(
    paymentAuthorizationHash []byte,
    payloads [][]byte,
    sellerKey *ec.PrivateKey,
) (*SignedContentDelivery, error)

// VerifyContentPayloads 针对被授权哈希验证交付批次：数量、顺序、逐项 SHA-256、
// seed/block 归属与协议期望长度。整个批次原子成功或失败；返回成员校验实际
// 使用的 seed，调用方可用它重算价格。
func VerifyContentPayloads(
    quoteTerms *FileQuoteTerms,
    contentHashes, payloads [][]byte,
    seed []byte,
) ([]byte, error)
```
