---
id: 003-content-request-spec
title: 003 · v4 Content Request Specification
---

# 003 · v4 Content Request Specification

The final wire shape of v4 is fixed and exclusive; pre-switch v4 shapes (duplicated keys, fee rate, base/after sequences, content type, single hash) are rejected outright.

```text
SignedContentRequest = [4, terms_cbor, buyer_signature]

terms_cbor = deterministic-CBOR([
    quote_terms_hash,        ; bstr .size 32
    refund_template_txid,    ; bstr .size 32
    payment_sequence,        ; uint: target state = previous + 1, <= 0xfffffffe
    seller_amount_after_sat, ; uint: absolute cumulative seller amount
    content_hashes_cbor,     ; bstr .cbor [1*64 content-hash], ordered & unique
    delivery_deadline_unix   ; int > 0, within quote expiry
])

buyer_signature = SignMessage(buyer_key, terms_cbor)
payment_authorization_hash = SHA-256(terms_cbor)
```

The outer version `4` does not enter the buyer signature. There is no inner version field. The terms carry no public keys and no fee rate; identity and fees are recovered from the OpeningProof bound to `refund_template_txid`. The authorization hash serves as the `PaymentAuthorizationHash` for subsequent 004, 005, and 007; it is a content-addressed lookup key into the saved original signed request and can never be decoded into pool identity, sequence, or amounts. The terms also supply the target `PaymentSequence` and absolute cumulative seller amount from which both sides later rebuild the 005 payment state transaction. The current version does not carry a negotiable arbitration amount; the construction layer always uses `ArbiterAmount = 0`.
