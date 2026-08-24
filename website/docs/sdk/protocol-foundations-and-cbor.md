---
id: protocol-foundations-and-cbor
title: 01 · Protocol foundations and CBOR
---

# 01 · Protocol foundations and CBOR

Return to the [SDK API framework](sdk-api-framework-design.md).

The current implementation provides the boundaries described here: `bitfs`, `pool`, `buyer.Workflow`, `seller.Workflow`, `arbitration.Workflow`, and `wire` are ready to use. Pseudocode on this page explains responsibilities; it does not replace the actual Go signatures.

## Design goal

An application should be able to complete a purchase in business order without understanding CBOR array positions, transaction-signature assembly, or non-final transaction-pool internals:

```text
Seller signs a quote
  -> Buyer opens a payment pool
  -> Buyer requests a seed or block
  -> Seller delivers content
  -> Buyer signs a cumulative payment
  -> Seller advances the deferred transaction
  -> Expiry refund / negotiated close / seller arbitration
```

## Package boundaries

The API has three layers: a pure protocol core, role workflows, and externally supplied ports. The old `HashGetTicket`, `proposal_id`, and session-pool APIs remain only in historical documentation and are not current entry points.

```text
bitfs/       Credentials, CBOR, signatures, and content checks for 001, 003, and 004
pool/        Generic 2-of-3 payment pools and BSV transaction checks for 002, 005, and 006
buyer/       Buyer workflow facade; produces the next credential or transaction to send
seller/      Seller workflow facade; verifies deliveries and advances deferred updates; delivery-context serialization is the calling application's responsibility
arbitration/ Evidence validation and transaction-signing facade for 007
wire/        Deterministic CBOR encoding, strict decoding, and dispatch for current messages
transport/   Optional application adapter layer; the SDK core does not depend on it
```

`pool` MUST NOT depend on quotes, seeds, file blocks, or BitFS content types. `bitfs` MUST NOT submit on-chain transactions. `wire` does not sign, access storage, or submit transactions; it handles exact CBOR bytes only. `buyer` and `seller` orchestrate these domains.

## Common conventions

```go
// package bitfs; package pool
// Both packages use a fixed-width SHA-256 reference for their own API types.
type Hash32 [32]byte

// package bitfs
// UnixSeconds is UTC Unix time in seconds, matching the fields in 001 and 003.
type UnixSeconds int64
```

- Public keys, signatures, raw transactions, and CBOR are `[]byte`; implementations MUST copy mutable input slices.
- Every `wire.Unmarshal…` function accepts deterministic CBOR only. Successful parsing is not successful business validation.
- Every `Verify…` function checks the exact original bytes and signature; implementations MUST NOT re-encode before verification.
- Functions that can produce external side effects accept `context.Context`.

### Error model

Callers should be able to choose retry, rejection, or user feedback by error category. Sentinel errors support `errors.Is`, with underlying causes wrapped where useful:

```go
var (
    ErrInvalidEvidence      error // CBOR, hashes, signatures, or transaction data are inconsistent.
    ErrQuoteExpired         error // The 001 quote has expired.
    ErrStalePaymentSequence error // The request or payment is based on a non-current pool state.
    ErrInsufficientBalance  error // The pool cannot cover the content and transaction fee.
    ErrNotExpired           error // The refund timelock has not been reached.
    ErrContentNotInSeed     error // The requested block is not committed by the quote's seed.
)
```

`ErrStalePaymentSequence` is an expected business outcome and should not be reported as an internal error.

## Unified CBOR message API

CBOR packing and unpacking belong to the SDK, not to HTTP, WebSocket, queue, or application code. Applications MUST NOT re-encode protocol objects with another CBOR library or convert structs to JSON and sign the result.

`wire` does not wrap the established 001–008 messages in a global envelope, which would alter their signed bytes and array layouts. The transport route, endpoint, or caller supplies the message kind; the CBOR body remains the exact deterministic bytes defined by each specification.

```go
// package wire
// Kind is known to the transport and selects a decoder; it never identifies a
// pool instance. Authentication documents carry no version or kind element of
// their own: the unified signature domain folds the outer version, the kind,
// and the exact document bytes into one signing input — Seller signs exactly
// arbitration_claim_cbor via SignWireDocument(1, 8, ...), the Arbiter signs
// exactly arbitration_receipt_cbor via SignWireDocument(1, 9, ...), the Buyer
// retrieval request signs exactly content_retrieval_request_cbor =
// [arbitration_claim_id, retrieval_nonce] via SignWireDocument(1, 10, ...),
// and Kind 11 carries the Arbiter's own unified signature over
// content_retrieval_result_cbor; its available branch binds the payload
// bundle through content_payloads_id and never embeds Kind 8/9 bytes.
// Messages that define RefundTemplateTxID carry it in the CBOR document. The
// 0201 presign request derives it from RefundTx and has no separate
// correlation ID field.
type Kind uint16

const (
    // Quote is a signed file quote.
    // Direction: seller -> buyer.
    Quote Kind = 1

    // PoolRefundPresignRequest requests the seller's refund signature.
    // Direction: buyer -> seller.
    PoolRefundPresignRequest Kind = 2

    // PoolRefundPresignResponse carries the seller's refund signature.
    // Direction: seller -> buyer.
    PoolRefundPresignResponse Kind = 3

    // FundingTransactionDelivery carries the signed funding transaction.
    // Direction: buyer -> seller.
    FundingTransactionDelivery Kind = 4

    // ContentRequest carries the signed content request and payment authorization.
    // Direction: buyer -> seller.
    ContentRequest Kind = 5

    // ContentDelivery carries the signed content payload.
    // Direction: seller -> buyer.
    ContentDelivery Kind = 6

    // CumulativePayment carries a cumulative payment update.
    // Direction: buyer -> seller.
    CumulativePayment Kind = 7

    // ArbitrationRequest carries evidence for arbitration.
    // Direction: seller -> arbiter.
    ArbitrationRequest Kind = 8

    // ArbitrationResponse carries the arbiter's signature result.
    // Direction: arbiter -> seller.
    ArbitrationResponse Kind = 9
)

// Packet is a transport-ready representation. Kind belongs in the outer
// route; CBOR must be transmitted and stored unchanged.
type Packet struct {
    Kind Kind
    CBOR []byte
}

// Marshal deterministically encodes the exact type selected by kind.
// A kind/type mismatch, invalid field length, or non-deterministic value
// returns ErrInvalidEvidence.
func Marshal(kind Kind, message any) (Packet, error)

// Unmarshal strictly decodes rawCBOR according to a caller-supplied kind. It
// rejects non-canonical CBOR, unknown versions, invalid array lengths, and
// kind/structure mismatches. Business validation is still required afterward.
func Unmarshal(kind Kind, rawCBOR []byte) (any, error)

// Typed helpers avoid any and type assertions in normal applications.
func MarshalQuote(message *bitfs.SignedFileQuote) ([]byte, error)
func UnmarshalQuote(rawCBOR []byte) (*bitfs.SignedFileQuote, error)
func MarshalRefundPresignRequest(message *pool.RefundPresignRequest) ([]byte, error)
func UnmarshalRefundPresignRequest(rawCBOR []byte) (*pool.RefundPresignRequest, error)
func MarshalRefundPresignResponse(message *pool.RefundPresignResponse) ([]byte, error)
func UnmarshalRefundPresignResponse(rawCBOR []byte) (*pool.RefundPresignResponse, error)
func MarshalFundingTransactionDelivery(message *pool.FundingTransactionDelivery) ([]byte, error)
func UnmarshalFundingTransactionDelivery(rawCBOR []byte) (*pool.FundingTransactionDelivery, error)
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

006 introduces no application-level close message. Closing uses raw transactions already retained from 002 and 005; applications should not invent a CBOR `CloseRequest`.

`Unmarshal` answers only whether bytes conform to a message schema. The role workflows subsequently validate signatures, quote expiry, payment-pool inputs, and amounts with the SDK's fixed verifiers — there are no caller-supplied verifier callbacks to configure. A decoder MUST NOT expose “decoded” as “verified” or “paid.”

Every protocol identity public key is encoded as a valid 33-byte compressed
secp256k1 key. The fixed validation layer rejects 65-byte uncompressed keys
before they can enter signed 001/003/004 terms or 002 pool evidence.

## Pure protocol API

These functions have no storage or network effects and are suitable for wallets, servers, CLIs, and tests. Signing takes the caller-parsed official BSV private key directly (`ec.PrivateKey` from `github.com/bsv-blockchain/go-sdk/primitives/ec`). There are no signer or verifier callbacks.

Every ordinary message signature goes through one unified path: `protocol.SignWireDocument(key, protocol.WireVersion, kind, documentCBOR)` builds the typed signing input `["bitfs/wire-signature", version, kind, exact_document_cbor]`, hashes it once with SHA-256, signs that pre-computed digest, enforces low-S DER, and re-checks the result against the role's derived public key through a fixed internal verifier before anything is returned. Callers never hash, wrap, or verify manually; Kind 6 for example signs exactly `content_delivery_cbor = [payment_authorization_id]`, never a bare hash. Transaction signatures use the fixed MultisigPool sighash (`ForkID|All`) and are never hashed a second time.

```go
// package bitfs
// NewSignedFileQuote validates quote terms, encodes the canonical file_quote_terms_cbor,
// signs those exact bytes with the seller's official BSV private key through
// SignWireDocument(1, 1, ...), and fixedly re-verifies the signature with the
// derived public key before returning a 001 credential.
func NewSignedFileQuote(
    terms *FileQuoteTerms,
    sellerKey *ec.PrivateKey,
    recommendedFilename string,
) (*SignedFileQuote, error)

// VerifyFileQuoteEvidence checks the unified seller signature and field
// constraints without reading any clock; expiry decisions stay with the
// caller, which reads system UTC once.
func VerifyFileQuoteEvidence(quote *SignedFileQuote) (*FileQuoteTerms, error)

// NewSignedContentRequest deterministically encodes the payment authorization
// and signs those exact bytes with the buyer's official BSV private key
// through SignWireDocument(1, 5, ...).
func NewSignedContentRequest(authorization *PaymentAuthorization, buyerKey *ec.PrivateKey) (*SignedContentRequest, error)

// VerifySignedContentRequest checks quote binding, pool participants, the
// buyer signature over the exact terms bytes, quote expiry, and the delivery
// deadline using system UTC read once at entry and the fixed SDK verifiers.
// VerifySignedContentRequestForOpening verifies only the pool binding and
// buyer signature for a local OpeningProof. Seller uses it while forming the
// new 007 Claim; OpeningProof itself is not placed on the Kind 8 wire.
// VerifySignedContentRequestWithSeed additionally proves that every requested
// block hash is present in the quote-bound seed.
func VerifySignedContentRequest(
    request *SignedContentRequest,
    quote *SignedFileQuote,
    opening PoolOpeningEvidence,
) (*PaymentAuthorization, error)

// NewSignedContentDelivery builds content_delivery_cbor =
// deterministic-CBOR([payment_authorization_id]), signs exactly that document
// through SignWireDocument(1, 6, ...) with the seller's official BSV private
// key, and attaches the canonically encoded ordered payload batch. Payloads
// are bound indirectly via the hashes committed in the referenced 003.
func NewSignedContentDelivery(
    paymentAuthorizationID protocol.PaymentAuthorizationID,
    payloads [][]byte,
    sellerKey *ec.PrivateKey,
) (*SignedContentDelivery, error)

// VerifyContentPayloads validates a delivered batch against the authorized
// hashes: count, order, per-item SHA-256, seed/block membership, and protocol
// expected lengths. The whole batch succeeds or fails atomically; it returns
// the seed used for membership checks so callers can recompute pricing.
func VerifyContentPayloads(
    quoteTerms *FileQuoteTerms,
    contentHashes, payloads [][]byte,
    seed []byte,
) ([]byte, error)
```
