---
id: 001-quote-credential-spec
title: "001 · BitFS Quote Credential Specification"
---

# 001 · BitFS Quote Credential Specification

## Encoding, signing, and hashing

All structures use RFC 8949 core deterministic CBOR. The quote is wire
Kind 1: a fixed five-element shell whose seller signature covers the exact
`file_quote_terms_cbor` through the unified `SignWireDocument(1, 1, ...)`
helper — the typed signing input `["bitfs/wire-signature", 1, 1,
file_quote_terms_cbor]` authenticates version and kind together with the
exact document bytes. No bare-hash signature exists.

```text
kind-1-file-quote = [
    1,                                  ; wire-version, injected by the encoder
    1,                                  ; wire kind
    file_quote_terms_cbor,
    seller_public_key,
    seller_file_quote_terms_signature   ; SignWireDocument(1, 1, ...)
]

file_quote_terms_id = SHA-256(file_quote_terms_cbor)
```

The normative CDDL truth is [`spec/v1/wire-messages.cddl`](https://github.com/bsv8/go-bitfs/blob/main/spec/v1/wire-messages.cddl).

## `FileQuoteTerms`

CBOR array positions are fixed as follows:

| Position | Field | Implementation Requirement |
|---:|---|---|
| 0 | `seed_hash` | MUST be 32 bytes. |
| 1 | `buyer_public_key` | Only this compressed public key MAY accept and sign subsequent purchase requests. |
| 2 | `seed_price_satoshis` | Seed price in satoshis. |
| 3 | `full_block_price_satoshis` | Full block price in satoshis. |
| 4 | `file_size_bytes` | Total file size in bytes. |
| 5 | `quote_expires_at_unix_seconds` | Quote expiration as a Unix timestamp in seconds. |
| 6 | `supported_arbiter_public_keys_cbor` | Independent deterministic CBOR of an array of arbiter public keys. |
| 7 | `recommended_filename` | Sanitized display suggestion; signed by the seller like every other term. |

The authentication document carries no version or kind field. The block
count MUST be derived from `file_size_bytes`: `0` maps to `0` blocks; a
positive value maps to `ceil(file_size_bytes / 262144)`. Each payload is at
most one MasterSeed block (256 KiB). The arbiter public key array MAY be
empty, but public keys within it MUST NOT be empty or duplicated.
`recommended_filename` MUST pass the sanitize rules before encoding and
signing; because it is part of the terms, two quotes differing only in the
filename have different `file_quote_terms_id` values.

## `SignedFileQuote`

The SDK type carries the exact child bytes plus the seller public key and
signature:

```text
SignedContentRequest-style fields:
  file_quote_terms_cbor              ; exact canonical bytes, never re-encoded
  seller_public_key                  ; verifies the terms signature
  seller_file_quote_terms_signature  ; SignWireDocument(1, 1, ...)
```

During verification, implementations MUST strictly decode and
deterministically re-encode `file_quote_terms_cbor`, then verify the unified
signature against the recovered seller key, followed by field widths, quote
expiration, and the arbiter array. Clients displaying the filename MUST
sanitize path separators and control characters; verification only checks
that the received field already satisfies the same sanitize rules and never
rewrites it silently.

## Subsequent references and retention

003 payment authorizations carry only `file_quote_terms_id`. The seller MUST
locate and re-verify the original quote credential by this ID; both parties
MUST retain the full quote credential until the associated payment settlement
and arbitration window has closed. For offline verification, migration, or
arbitration, the full quote credential together with subsequent credentials
constitutes the evidence package.

## Tail block

Quotes do not carry a tail-block price. Implementations MUST calculate the
tail block proportionally based on its actual length relative to one MasterSeed
block, applying a 10% calculation tolerance concession on the seller's side.
This rule is not the sole integer formula for automatic arbitration; the
cumulative amount signed out by the buyer in 005 is the final enforceable
amount.

## Go API

```go
// 直接私钥必须经唯一的 local signer 适配器进入；HSM/KMS 实现同一 Signer 接口。
sellerSigner, err := protocol.NewPrivateKeySigner(sellerPrivateKey)
arbiters := [][]byte{arbiterPublicKey}
supportedCBOR, err := content.EncodeSupportedArbiterPublicKeys(arbiters)
terms := &content.FileQuoteTerms{
    SeedHash:                       seedHash,
    BuyerPublicKey:                 buyerPublicKey,
    SeedPriceSatoshis:              10,
    FullBlockPriceSatoshis:         100,
    FileSizeBytes:                  fileSizeBytes,
    QuoteExpiresAtUnixSeconds:      expiresAtUnixSeconds,
    SupportedArbiterPublicKeysCBOR: supportedCBOR,
    RecommendedFilename:            "download.bin", // sanitize 后的唯一文件名来源
}
signedQuote, err := content.NewSignedFileQuote(ctx, terms, sellerSigner)
outboundKind1, err := wire.EncodeFileQuote(signedQuote) // exact bytes：先持久化再发送
terms, err := content.VerifyFileQuoteEvidence(signedQuote)
quoteID, err := content.FileQuoteTermsID(signedQuote.FileQuoteTermsCBOR)
```

Signing capability enters only through the constrained `protocol.Signer`
port; signing and verification go through the fixed `SignWireDocument`
helpers, so callers supply no signing domain, verifier callback, or curve
implementation. Time-sensitive checks take the caller's explicit facts
(`protocol.Facts`); the SDK never reads a clock.
