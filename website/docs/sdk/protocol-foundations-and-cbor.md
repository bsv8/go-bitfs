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
seller/      Seller workflow facade; owns the delivery latch, acceptance, and deferred updates
arbitration/ Evidence validation and transaction-signing facade for 007
wire/        Deterministic CBOR encoding, strict decoding, and dispatch for current messages
transport/   Optional application adapter layer; the SDK core does not depend on it
```

`pool` MUST NOT depend on quotes, seeds, file blocks, or BitFS content types. `bitfs` MUST NOT submit on-chain transactions. `wire` does not sign, access storage, or submit transactions; it handles exact CBOR bytes only. `buyer` and `seller` orchestrate these domains.

## Common conventions

```go
// Hash32 is a SHA-256 result. Public APIs do not accept ambiguous hash strings.
type Hash32 [32]byte

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
    ErrPoolBusy             error // The seller already has an unfinished delivery on this pool.
    ErrStalePaymentSequence error // The request or payment is based on a non-current pool state.
    ErrInsufficientBalance  error // The pool cannot cover the content and transaction fee.
    ErrNonFinalRejected     error // The BSV non-final pool rejected the update.
    ErrFinalRejected        error // The BSV node rejected the final transaction.
    ErrNotExpired           error // The refund timelock has not been reached.
    ErrContentNotInSeed     error // The requested block is not committed by the quote's seed.
)
```

`ErrPoolBusy` and `ErrStalePaymentSequence` are expected business outcomes and should not be reported as internal errors.

## Unified CBOR message API

CBOR packing and unpacking belong to the SDK, not to HTTP, WebSocket, queue, or application code. Applications MUST NOT re-encode protocol objects with another CBOR library or convert structs to JSON and sign the result.

`wire` does not wrap the established 001–007 messages in a global envelope, which would alter their signed bytes and array layouts. The transport route, endpoint, or caller supplies the message kind; the CBOR body remains the exact deterministic bytes defined by each specification.

```go
// package wire
// Kind is known to the transport and selects a decoder. It is not part of a
// signed 001–007 CBOR body.
type Kind uint16

const (
    Quote                     Kind = 1 // 001 SignedFileQuote.
    PoolRefundPresignRequest  Kind = 2 // 002 buyer -> seller.
    PoolRefundPresignResponse Kind = 3 // 002 seller -> buyer.
    PoolFundingTxDelivery     Kind = 4 // 002 buyer -> seller.
    ContentRequest            Kind = 5 // 003 buyer -> seller.
    ContentDelivery           Kind = 6 // 004 seller -> buyer.
    CumulativePayment         Kind = 7 // 005 buyer -> seller.
    ArbitrationRequest        Kind = 8 // 007 seller -> arbiter.
    ArbitrationResponse       Kind = 9 // 007 arbiter -> seller.
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

006 introduces no application-level close message. Closing uses raw transactions already retained from 002 and 005; applications should not invent a CBOR `CloseRequest`.

`Unmarshal` answers only whether bytes conform to a message schema. `VerifyQuote`, `VerifyContentDelivery`, and `MultisigPoolPort.Verify…` subsequently validate signatures, quote expiry, payment-pool inputs, and amounts. A decoder MUST NOT expose “decoded” as “verified” or “paid.”

## Pure protocol API

These functions have no storage or network effects and are suitable for wallets, servers, CLIs, and tests.

```go
// CreateQuote signs deterministic FileQuoteTerms CBOR and creates a 001
// credential. recommendedFilename is display-only and is not signed.
func CreateQuote(
    ctx context.Context,
    draft bitfs.FileQuoteTerms,
    recommendedFilename string,
    seller Signer,
) (*bitfs.SignedFileQuote, error)

// VerifyQuote checks the seller signature, field constraints, and expiry and
// returns independently parsed terms.
func VerifyQuote(
    quote *bitfs.SignedFileQuote,
    now UnixSeconds,
    verifier SignatureVerifier,
) (*bitfs.FileQuoteTerms, error)

// CreateContentRequest creates buyer-signed 003. poolRef identifies SpendTxID
// and the current BasePaymentSequence; content is a Seed or Block plus hash.
// It does not lock a pool, download content, or create a payment transaction.
func CreateContentRequest(
    ctx context.Context,
    quote *bitfs.SignedFileQuote,
    poolRef pool.Reference,
    selectedArbiterPubKey []byte,
    content bitfs.ContentRef,
    deliveryDeadline UnixSeconds,
    buyer Signer,
) (*bitfs.SignedContentRequest, error)

// VerifyContentDelivery checks the 004 reference to 003, seller signature,
// content hash, and exact length. It writes to sink only after every check.
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
