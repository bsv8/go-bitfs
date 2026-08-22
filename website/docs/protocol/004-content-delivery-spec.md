---
id: 004-content-delivery-spec
title: 004 · v4 Content delivery credential specification
---

# 004 · v4 Content delivery credential specification

004 uses protocol major `4` as a fixed four-element shell. There is no separate DeliveryTerms layer, no pool ID, no content hashes, and no payload inside any signed structure; pre-switch v4 shapes are rejected outright.

```text
SignedContentDelivery = [
    4,                                       ; shell version, not signed
    payment_authorization_hash,              ; bstr .size 32 = SHA-256(003 terms_cbor)
    seller_payment_authorization_hash_signature,
    content_payloads_cbor                    ; bstr .cbor [1*64 content-payload]
]

seller_payment_authorization_hash_signature =
    SignMessage(seller_private_key, payment_authorization_hash)

content_payloads_cbor = deterministic-CBOR(payloads)   ; embedded as bstr
payloads[i] ordered exactly like the hashes in the referenced 003;
each payload is non-empty and at most one MasterSeed block.
```

Acceptance order for the buyer: locate the saved original 003 by `PaymentAuthorizationHash`; recompute and byte-compare the hash; load the OpeningProof and current PaymentState and re-derive the pool binding; verify the seller signature over the bare 32-byte hash with the OpeningProof's seller key; strictly decode the payloads and verify count, order, per-item SHA-256, membership, and expected lengths; recompute the aggregate price, target sequence, and absolute cumulative amount. Only when every item succeeds does the buyer construct and sign exactly one 005.
