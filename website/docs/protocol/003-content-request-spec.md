---
id: 003-content-request-spec
title: 003 · Content Request Specification
---

# 003 · Content Request Specification

The final wire shape of BitFS v1 is fixed and exclusive; legacy shapes
(duplicated keys, fee rate, base/after sequences, content type, single hash)
are rejected outright. There is no compatible decoder and no presence
guessing inside `protocol.WireVersion = 1`.

```text
kind-5-content-request = [
    1,                                   ; wire-version, injected by the encoder
    5,                                   ; wire kind
    payment_authorization_cbor,
    buyer_payment_authorization_signature
]

payment_authorization_cbor = deterministic-CBOR([
    file_quote_terms_id,           ; bstr .size 32 = SHA-256(exact quote terms cbor)
    refund_template_txid,          ; bstr .size 32; fixed transaction TxID algorithm
    payment_sequence,              ; uint .le 4294967294: target state = previous + 1
    seller_amount_after_satoshis,  ; uint: absolute cumulative seller amount
    content_hashes_cbor,           ; bstr .cbor [1*64 sha256], ordered & unique
    delivery_deadline_unix_seconds ; int > 0, within quote expiry
])

buyer_payment_authorization_signature =
    SignWireDocument(buyer_key, 1, 5, payment_authorization_cbor)

payment_authorization_id = SHA-256(payment_authorization_cbor)
```

The authentication document carries no outer version or kind, no public keys,
and no fee rate; identity and fees are recovered from the OpeningProof bound
to `refund_template_txid`. `SignWireDocument` signs the typed input
`["bitfs/wire-signature", 1, 5, payment_authorization_cbor]`, so version and
kind are authenticated together with the exact document bytes.

`payment_authorization_id` is the `PaymentAuthorizationID` for subsequent
004, 005, and 007; it is a content-addressed lookup key into the saved
original signed request and can never be decoded into pool identity,
sequence, or amounts. The authorization also supplies the target
`PaymentSequence` and absolute cumulative seller amount from which both sides
later rebuild the 005 payment state transaction. For 007, the seller uses the
saved 003 together with the validated 004 payload bundle to form the Claim;
the arbiter independently rebuilds from the Claim's source context. The wire
carries no negotiable arbitration amount; the calling application decides the
positive arbiter fee explicitly when submitting 007.
