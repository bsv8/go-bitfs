---
id: 001-quote-credential-spec
title: "001 · BitFS Quote Credential Specification"
---

# 001 · BitFS Quote Credential Specification

## Encoding, Signing, and Hashing

All structures use RFC 8949 core deterministic CBOR. `TermsCBOR` MUST be the raw deterministic CBOR bytes of `FileQuoteTerms`:

```text
TermsSignature = Sign_seller(TermsCBOR)
Verify(SellerPubkey, TermsCBOR, TermsSignature)
FileQuoteTermsHash = SHA256(TermsCBOR)
```

No signature domain is used. Implementations MUST verify `TermsSignature` solely against the quote terms as described above.

The normative CDDL is located at [`https://github.com/bsv8/go-bitfs/blob/main/spec/file-quote.cddl`](https://github.com/bsv8/go-bitfs/blob/main/spec/file-quote.cddl).

## `FileQuoteTerms`

CBOR array positions are fixed as follows:

| Position | Field | Implementation Requirement |
|---:|---|---|
| 0 | `version` | Currently `1`. |
| 1 | `seed_hash` | MUST be 32 bytes. |
| 2 | `buyer_pubkey` | Only this public key MAY accept and sign subsequent purchase requests. |
| 3 | `seed_price_sat` | Seed price in satoshis. |
| 4 | `full_block_price_sat` | Full 256 KiB block price in satoshis. |
| 5 | `file_size` | Total file size in bytes. |
| 6 | `quote_expires_at_unix` | Quote expiration as a Unix timestamp in seconds. |
| 7 | `supported_arbiter_pubkeys_cbor` | Independent deterministic CBOR of an array of arbiter public keys. |

The block count MUST be derived from `file_size`: `0` maps to `0` blocks; a positive value maps to `ceil(file_size / 262144)`. The current seed payload limit is 256 KiB; the maximum quote size is 8192 blocks. The arbiter public key array MAY be empty, but public keys within it MUST NOT be empty or duplicated.

## `SignedFileQuote`

CBOR array positions are fixed as follows:

| Position | Field | Implementation Requirement |
|---:|---|---|
| 0 | `version` | Currently `1`. |
| 1 | `terms_cbor` | Full raw CBOR of `FileQuoteTerms`. |
| 2 | `seller_pubkey` | Used to verify the terms signature. |
| 3 | `terms_signature` | Seller's signature over `terms_cbor`. |
| 4 | `recommended_filename` | Display suggestion only; MUST NOT be treated as ground truth for content, price, or identity. |

During verification, implementations MUST re-decode and deterministically re-encode `terms_cbor`, then verify the signature, field lengths, quote expiration, and arbiter array. Clients displaying the filename MUST sanitize path separators and control characters.

## Subsequent References and Retention

Normal messages in 003 carry only `FileQuoteTermsHash`. The seller MUST locate and re-verify the original quote credential by this hash; both parties MUST retain the full quote credential until the associated payment settlement and arbitration window has closed. For offline verification, migration, or arbitration, the full quote credential together with subsequent credentials constitutes the evidence package.

## Tail Block

Quotes do not carry a tail-block price. Implementations MUST calculate the tail block proportionally based on its actual length relative to 256 KiB, applying a 10% calculation tolerance concession on the seller's side. This rule is not the sole integer formula for V1 automatic arbitration; the cumulative amount signed out by the buyer in 005 is the final enforceable amount.

## Go API

```go
arbiterCBOR, err := bitfs.EncodeSupportedArbiterPubkeys(arbiterPubkeys)
terms := &bitfs.FileQuoteTerms{
    SeedHash:                    seedHash,
    BuyerPubkey:                 buyerPubkey,
    SeedPriceSat:                10,
    FullBlockPriceSat:           100,
    FileSize:                    fileSize,
    QuoteExpiresAtUnix:          expiresAtUnix,
    SupportedArbiterPubkeysCBOR: arbiterCBOR,
}
quote, err := bitfs.NewSignedFileQuote(terms, sellerPubkey, "download.bin", signTermsCBOR)
verifiedTerms, err := bitfs.VerifySignedFileQuote(quote, verifySellerTermsSignature)
```

The caller is responsible for specifying public key format, signing algorithm, and signature verifier; the library does not bind to any wallet or elliptic curve implementation.
