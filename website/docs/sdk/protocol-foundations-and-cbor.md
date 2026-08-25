---
id: protocol-foundations-and-cbor
title: 01 · Protocol foundations and CBOR
---

# 01 · Protocol foundations and CBOR

Return to the [SDK API framework](sdk-api-framework-design.md).

The current implementation provides the boundaries described here: `protocol`, `content`, `pool`, `arbitration`, `buyer.Workflow`, `seller.Workflow`, `arbiter.Workflow`, and `wire` are ready to use. Pseudocode on this page explains responsibilities; it does not replace the actual Go signatures.

## Design goal

An application should be able to complete a purchase in business order without understanding CBOR array positions, transaction-signature assembly, or non-final transaction-pool internals:

```text
Seller signs a quote
  -> Buyer opens a payment pool
  -> Buyer requests a seed or block
  -> Seller delivers content
  -> Buyer signs a cumulative payment
  -> Seller advances the deferred transaction
  -> Expiry refund / negotiated close / arbiter custody signing
```

## Package boundaries

The API has four layers: shared protocol foundations, pure domain packages, an exact-bytes wire layer, and the role workflows that are the only recommended application path.

```text
protocol/     Shared foundations: constrained Signer port (+ NewPrivateKeySigner),
              explicit Facts{Now, BlockHeight}, typed IDs (fq_/pa_/ac_/cr_/cp_
              prefixed text forms), structured errors with ErrorCode classification
content/      Credentials, canonical CBOR, signatures, hashes, pricing, and content
              checks for 001, 003, and 004; immutable VerifiedQuote verified value
pool/         Generic 2-of-3 payment pools and BSV transaction checks for 002,
              005, and 006; opaque VerifiedOpening / VerifiedPaymentState /
              VerifiedSignedTransaction values
arbitration/  Pure 007/008 custody-evidence domain functions; no role state
wire/         Typed encoders and strict decoders over exact bytes returning
              immutable wire.Artifact values
buyer/, seller/, arbiter/
              Role workflow facades; produce the next Artifact, transaction, or
              opaque checkpoint to persist. Delivery-context serialization is the
              calling application's responsibility
```

`pool` MUST NOT depend on quotes, seeds, file blocks, or BitFS content types. `content` MUST NOT submit on-chain transactions. `wire` does not sign, access storage, or submit transactions; it handles exact CBOR bytes only. `buyer`, `seller`, and `arbiter` orchestrate these domains; applications should call them instead of assembling domain calls by hand.

## Common conventions

```go
// package protocol
// Facts 是调用方显式传入的观测事实；时间敏感操作要求非零 Now，
// 高度敏感操作要求非零 BlockHeight。SDK 绝不回退系统时钟或猜测高度。
type Facts struct {
    Now         time.Time
    BlockHeight BlockHeight
}
```

- Public keys, signatures, raw transactions, and CBOR are `[]byte`; implementations MUST copy mutable input slices.
- Every wire parse accepts deterministic CBOR only. Successful parsing is not successful business validation.
- Every `Verify…` function checks the exact original bytes and signature; implementations MUST NOT re-encode before verification.
- Functions that can produce external side effects accept `context.Context`.

### Error model

Callers branch on one stable error taxonomy carried by `*protocol.Error{Op, Code, Kind, Field, Cause}`. Applications assert categories — never error text:

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
// 分类断言：应用分支只看 Code，绝不匹配错误文本。
if protocol.IsCode(err, protocol.CodeExpired) { /* ... */ }
code, ok := protocol.CodeOf(err) // 取回第一个分类
```

`CodeStateConflict` is an expected business outcome (stale sequence) and should not be reported as an internal error.

## Exact-bytes wire Artifacts

CBOR packing and unpacking belong to the SDK, not to HTTP, WebSocket, queue, or application code. Applications MUST NOT re-encode protocol objects with another CBOR library or convert structs to JSON and sign the result.

The wire layer is built around one value type:

```go
// package wire
// Artifact 是已通过严格解析的不可变 exact bytes：它证明完整报文的规范结构，
// 不代表签名、金额、身份或业务状态已验证。Bytes() 返回副本，调用方无法修改
// 内部字节。
type Artifact struct{ /* 字段私有 */ }

func Parse(raw []byte) (Artifact, error)          // 自读版本与 Kind，分派严格 decoder
func ParseAs(expected Kind, raw []byte) (Artifact, error) // 额外校验路由声明的 Kind
func (a Artifact) Kind() Kind
func (a Artifact) Bytes() []byte                  // exact bytes 的副本；持久化后原样发送

const (
    FileQuote Kind = 1   // 卖方 -> 买方
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
artifact, err := wire.EncodeFileQuote(signedQuote)      // Kind 1
decoded, err := wire.DecodeFileQuote(artifact)          // *content.SignedFileQuote
```

Wire v1 is unchanged: every complete message starts with `[protocol.WireVersion, wire_kind, ...]`, the outer pair is injected by each owning encoder, checked by every strict decoder, and folded into ordinary message signatures through `protocol.SignWireDocument`. Authentication documents carry no version or kind element of their own. Messages that define `RefundTemplateTxID` carry it in the CBOR document; the 0201 presign request derives it from RefundTx and has no separate correlation-ID field.

006 introduces no application-level close message. Closing uses raw transactions already retained from 002 and 005; applications should not invent a CBOR `CloseRequest`.

A parsed Artifact answers only whether bytes conform to a message schema. The role workflows subsequently validate signatures, quote expiry, payment-pool inputs, and amounts with the SDK's fixed verifiers — there are no caller-supplied verifier callbacks to configure. A decoder MUST NOT expose "decoded" as "verified" or "paid."

Every protocol identity public key is encoded as a valid 33-byte compressed secp256k1 key. The fixed validation layer rejects 65-byte uncompressed keys before they can enter signed 001/003/004 terms or 002 pool evidence.

## Pure domain API

These functions have no storage or network effects and are suitable for wallets, servers, CLIs, and tests. Signing goes through the constrained signer port — never a raw private-key parameter. Local software keys enter through `protocol.NewPrivateKeySigner(privateKey)` where `privateKey` is the caller-parsed official BSV key (`ec.PrivateKey` from `github.com/bsv-blockchain/go-sdk/primitives/ec`). There are no verifier callbacks.

Every ordinary message signature goes through one unified path inside the SDK: the digest over the typed signing input `["bitfs/wire-signature", version, kind, exact_document_cbor]` is constructed once, handed to the Signer, enforced low-S DER, and re-checked against the role's fixed public key before anything is returned. Callers never hash, wrap, or verify manually. Transaction signatures use the fixed MultisigPool sighash (`ForkID|All`) and are never hashed a second time.

```go
// package content
// NewSignedFileQuote validates quote terms, encodes the canonical
// file_quote_terms_cbor, signs those exact bytes through the constrained
// signer, and fixedly re-verifies the signature before returning a 001
// credential. RecommendedFilename 已在 terms 中完成 sanitize。
func NewSignedFileQuote(ctx context.Context, terms *FileQuoteTerms, signer protocol.Signer) (*SignedFileQuote, error)

// VerifyFileQuoteEvidence checks the unified seller signature and field
// constraints without reading any clock.
func VerifyFileQuoteEvidence(quote *SignedFileQuote) (*FileQuoteTerms, error)

// VerifySignedFileQuote additionally enforces quote expiry against one
// explicitly supplied time fact; 角色 API 用 facts.Now 调用它。
func VerifySignedFileQuote(quote *SignedFileQuote, at time.Time) (*FileQuoteTerms, error)

// NewSignedContentRequest deterministically encodes the payment authorization
// and signs those exact bytes with the buyer signer.
func NewSignedContentRequest(ctx context.Context, authorization *PaymentAuthorization, signer protocol.Signer) (*SignedContentRequest, error)

// CheckContentRequestTiming compares quote expiry and delivery deadline
// against one explicit time fact（时间比较的唯一入口，无内部读钟）。
func CheckContentRequestTiming(requestTerms *PaymentAuthorization, quoteTerms *FileQuoteTerms, at time.Time) error

// VerifyContentPayloadsContext validates a delivered batch against the
// authorized hashes: count, order, per-item SHA-256, seed/block membership, and
// protocol expected lengths. The whole batch succeeds or fails atomically; it
// returns the seed actually used so callers can recompute pricing.
func VerifyContentPayloadsContext(ctx context.Context, quoteTerms *FileQuoteTerms, contentHashes, payloads [][]byte, seed []byte) ([]byte, error)
```

The role workflows in [03 · Role workflow API](role-workflow-api.md) compose these pieces; applications should prefer them over calling domain functions directly.
