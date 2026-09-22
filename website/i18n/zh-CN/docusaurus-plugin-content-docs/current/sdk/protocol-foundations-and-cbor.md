---
id: protocol-foundations-and-cbor
title: 01 · 协议基础与 CBOR
---

# 01 · 协议基础与 CBOR

返回 [SDK API 框架入口](sdk-api-framework-design.md)。

当前代码已落地本页的全部边界：`protocol`、`content`、`pool`、`arbitration`、`buyer`/`seller`/`arbiter` 的纯函数步骤和 `wire` 均可直接使用；本文中的伪代码用于说明职责，不替代 Go 包的实际签名。

## 设计目标

使用者应能沿业务顺序完成一次购买，而不需要理解 CBOR 数组位置、交易签名拼接或非最终交易池细节：

```text
卖方签报价
  -> 买方开费用池
  -> 买方请求 seed / block
  -> 卖方交付内容
  -> 买方签累计支付
  -> 卖方推进远期交易
  -> 到期退款 / 协商关闭 / 仲裁托管签署
```

## 包边界

新 API 采用四层结构：共享协议基础、纯领域包、exact bytes wire 层，以及作为唯一推荐应用入口的角色纯函数步骤。

```text
protocol/     共享基础：受约束 Signer 端口（+ NewPrivateKeySigner）、显式
              Facts{Now, BlockHeight}、typed ID（fq_/pa_/ac_/cr_/cp_ 文本前缀）、
              带 ErrorCode 分类的结构化错误
content/      001、003、004 的凭证、规范 CBOR、签名、哈希、定价与内容校验；
              不可变 VerifiedQuote verified 值
pool/         002、005、006 的通用 2-of-3 费用池与 BSV 交易校验；不透明
              VerifiedOpening / VerifiedPaymentState / VerifiedSignedTransaction
arbitration/  007/008 托管证据的纯领域函数；无角色状态
wire/         面向 exact bytes 的类型化 encoder 与严格 decoder，返回不可变
              wire.Artifact
buyer/, seller/, arbiter/
              角色纯函数步骤：产生下一个待发送 Artifact、交易或普通证据包
              的 opaque checkpoint。交付上下文的串行化由调用方应用负责
```

`pool/` 不得引用报价、seed、文件块或 BitFS 内容类型；`content/` 不得自行提交链上交易。`wire/` 不签名、不访问存储、不提交交易，只处理精确 CBOR bytes。`buyer/`、`seller/`、`arbiter/` 编排上述领域；应用应优先调用角色 API，而不是手工拼装领域函数。

## 通用约定

```go
// package protocol
// Facts 是调用方显式传入的观测事实：时间敏感操作要求非零 Now，
// 高度敏感操作要求非零 BlockHeight。SDK 绝不回退系统时钟或猜测高度。
type Facts struct {
    Now         time.Time   // 本操作唯一时间事实（UTC）
    BlockHeight BlockHeight // 本操作唯一高度事实
}
```

- 公钥、签名、原始交易和 CBOR 均使用 `[]byte`；实现必须复制外部传入的可变切片。
- 每个 wire 解析入口只接受 deterministic CBOR；解析成功不等于业务校验成功。
- 每个 `Verify…` 函数均验证精确原始字节及签名；不得“重新编码后再验”。
- 所有会产生外部副作用的函数接受 `context.Context`。

### 错误模型

调用者根据唯一稳定的错误分类决定重试、拒绝还是提示用户。分类由 `*protocol.Error{Op, Code, Kind, Field, Cause}` 承载；应用只做分类断言——绝不匹配错误文本：

```go
// package protocol
type ErrorCode string

const (
    CodeMalformedWire        // 报文结构、数组形状或字段宽度畸形
    CodeNonCanonical         // 结构合法但编码不是 deterministic CBOR
    CodeUnsupportedVersion   // wire version 不是 1
    CodeUnsupportedKind      // Kind 不在 1..11 或与路由声明不一致
    CodeInvalidSignature     // 消息签名或交易签名验证失败
    CodeInvalidEvidence      // 哈希不匹配、池绑定失败、金额守恒破坏等
    CodeUnauthorized         // 角色公钥与操作者身份不符
    CodeExpired              // 报价过期、交付截止已过或退款锁定已到期
    CodeNotMatured           // 退款锁定尚未到期（正向操作被拒）
    CodeStateConflict        // 序号陈旧、checkpoint 与证据错配
    CodeInsufficientBalance  // 付款超出资金池余额或容量
    CodeCanceled             // context 取消或超时
    CodeSignerUnavailable    // 密钥托管方暂时无法完成签名
)
```

```go
// 分类断言：应用分支只看 Code。
if protocol.IsCode(err, protocol.CodeExpired) { /* ... */ }
code, ok := protocol.CodeOf(err) // 取回第一个分类
```

`CodeStateConflict`（陈旧序号）是可预期的业务结果，不应被报告为“内部错误”。

## exact bytes 的 wire Artifact

CBOR 的打包与解包属于 SDK，不属于 HTTP、WebSocket、队列或应用代码。应用不得直接使用第三方 CBOR 库重编码协议对象；也不得把结构体 JSON 化后再自行签名。

wire 层围绕一个值类型构建：

```go
// package wire
// Artifact 是已通过严格解析的不可变 exact bytes：它证明完整报文的规范结构，
// 不代表签名、金额、身份或业务状态已验证。Bytes() 返回副本，调用方无法修改
// 内部字节，输入 raw 的后续变异也不影响 Artifact。
type Artifact struct{ /* 字段私有 */ }

func Parse(raw []byte) (Artifact, error)                  // 自读版本与 Kind，分派严格 decoder
func ParseAs(expected Kind, raw []byte) (Artifact, error) // 额外校验路由声明的 Kind
func (a Artifact) Kind() Kind
func (a Artifact) Bytes() []byte                          // exact bytes 副本；持久化后原样发送

const (
    FileQuote Kind = 1                   // 卖方 -> 买方
    RefundPresignRequest Kind = 2        // 买方 -> 卖方
    RefundPresignResponse Kind = 3       // 卖方 -> 买方
    FundingTransactionDelivery Kind = 4  // 买方 -> 卖方
    ContentRequest Kind = 5              // 买方 -> 卖方
    ContentDelivery Kind = 6             // 卖方 -> 买方
    PaymentUpdate Kind = 7               // 买方 -> 卖方
    ArbitrationRequest Kind = 8          // 卖方 -> 仲裁方
    ArbitrationResponse Kind = 9         // 仲裁方 -> 卖方
    ContentRetrievalRequest Kind = 10    // 买方 -> 仲裁方
    ContentRetrievalResponse Kind = 11   // 仲裁方 -> 买方
)

// 每个 Kind 恰好一个类型化 encoder（返回 transport-ready Artifact）与一个
// 类型化 decoder（收 Artifact，返回深拷贝领域 DTO）。普通应用不需要直接使用
// decoder——角色 API 内部调用它们。
artifact, err := wire.EncodeFileQuote(signedQuote) // Kind 1
decoded, err := wire.DecodeFileQuote(artifact)     // *content.SignedFileQuote
```

Wire v1 保持不变：每条完整报文都以 `[protocol.WireVersion, wire_kind, ...]` 开头，外层版本/kind 对由各自的 encoder 注入、每个严格 decoder 复核，并通过 `protocol.SignWireDocument` 纳入普通消息签名。认证文档自身不携带版本或 kind 元素。定义了 `RefundTemplateTxID` 的报文在 CBOR 文档中携带它；0201 预签请求从 RefundTx 推导该值，不包含单独的关联 ID 字段。

006 没有新的应用层关闭报文，关闭行为使用 002/005 中已保存的原始交易，不应虚构新的 CBOR `CloseRequest`。

解析得到的 Artifact 只回答“字节是否符合某类报文模式”；随后由角色纯函数步骤使用 SDK 固定验证器校验签名、报价有效期、费用池输入和金额——不存在需要调用方配置的签名验证回调。解码器绝不能把“成功解码”暴露为“已验证”或“已付款”。

所有协议身份公钥都必须编码为合法的 33 字节压缩 secp256k1 公钥。固定验证层会在它们进入签名的 001/003/004 条款或 002 费用池证据前拒绝 65 字节未压缩公钥。

## 纯领域 API

这些函数没有存储或网络副作用，适合钱包、服务端、CLI 和测试直接使用。签名一律走受约束 Signer 端口——绝不接收裸私钥参数。本地软件私钥经 `protocol.NewPrivateKeySigner(privateKey)` 进入（`privateKey` 为调用方解析的官方 BSV 私钥，即 `github.com/bsv-blockchain/go-sdk/primitives/ec` 的 `ec.PrivateKey`）。不存在 signer 或 verifier 回调。

SDK 内部所有普通消息签名都走唯一统一路径：先构造类型化签名输入 `["bitfs/wire-signature", version, kind, exact_document_cbor]` 的 digest，交给 Signer 签名，强制 low-S DER，并在返回前由固定内部验证器对照角色公钥复验。调用方绝不手工哈希、包装或验签。交易签名使用固定的 MultisigPool sighash（`ForkID|All`），绝不做二次哈希。

```go
// package content
// NewSignedFileQuote 验证报价条款，编码规范 file_quote_terms_cbor，
// 经受约束 Signer 为这些精确字节签名，并在返回 001 凭证前固定复验签名。
// RecommendedFilename 已在 terms 中完成 sanitize。
func NewSignedFileQuote(ctx context.Context, terms *FileQuoteTerms, signer protocol.Signer) (*SignedFileQuote, error)

// VerifyFileQuoteEvidence 校验统一卖方签名与字段约束；不读任何时钟。
func VerifyFileQuoteEvidence(quote *SignedFileQuote) (*FileQuoteTerms, error)

// VerifySignedFileQuote 额外按一份显式时间事实强制报价未过期；
// 角色 API 用 facts.Now 调用它。
func VerifySignedFileQuote(quote *SignedFileQuote, at time.Time) (*FileQuoteTerms, error)

// NewSignedContentRequest 确定性编码付款授权，并用买方 Signer 签署这些精确字节。
func NewSignedContentRequest(ctx context.Context, authorization *PaymentAuthorization, signer protocol.Signer) (*SignedContentRequest, error)

// CheckContentRequestTiming 把报价有效期与交付截止同一份显式时间事实比较
// （时间比较的唯一入口，内部不读钟）。
func CheckContentRequestTiming(requestTerms *PaymentAuthorization, quoteTerms *FileQuoteTerms, at time.Time) error

// VerifyContentPayloadsContext 针对被授权哈希验证交付批次：数量、顺序、逐项
// SHA-256、seed/block 归属与协议期望长度。整个批次原子成功或失败；返回成员
// 校验实际使用的 seed，调用方可用它重算价格。
func VerifyContentPayloadsContext(ctx context.Context, quoteTerms *FileQuoteTerms, contentHashes, payloads [][]byte, seed []byte) ([]byte, error)
```

[03 · 角色纯函数 API](role-workflow-api.md) 中的步骤函数负责组合以上能力；普通应用应优先使用它们，而不是直接调用领域函数。
