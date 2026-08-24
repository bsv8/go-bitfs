---
id: 004-content-delivery-spec
title: 004 · Content delivery credential specification
---

# 004 · Content delivery credential specification

004 is wire Kind 6: a fixed five-element shell whose seller signature covers
the exact `content_delivery_cbor` through the unified
`SignWireDocument(1, 6, ...)` helper. There is no separate DeliveryTerms
layer, no pool ID, and no content hashes inside the signed document; the
payload batch travels as an attachment bound indirectly by the referenced
payment authorization.

```text
kind-6-content-delivery = [
    1,                                    ; wire-version, injected by the encoder
    6,                                    ; wire kind
    content_delivery_cbor,
    seller_content_delivery_signature,    ; SignWireDocument(1, 6, ...)
    content_payloads_cbor                 ; attachment, not signed directly
]

content_delivery_cbor = deterministic-CBOR([
    payment_authorization_id   ; bstr .size 32 = SHA-256(exact 003 payment authorization)
])

content_payloads_cbor = deterministic-CBOR([1*64 payload])
payloads[i] ordered exactly like the hashes in the referenced 003;
each payload is non-empty and at most one MasterSeed block.
```

Payload binding never relies on presence or trust:

```text
seller signature -> content_delivery_cbor -> payment_authorization_id
  -> payment_authorization_cbor -> ordered content_hashes_cbor
  -> SHA-256(content_payloads[i])
```

Acceptance order for the buyer: locate the saved original 003 by its
`PaymentAuthorizationID`; strictly decode `content_delivery_cbor` and require
it to commit to exactly that ID; verify the seller signature over the exact
document with the OpeningProof's seller key; strictly decode the payloads and
verify count, order, per-item SHA-256, membership, and expected lengths;
recompute the aggregate price, target sequence, and absolute cumulative
amount. Only when every item succeeds does the buyer build and sign the
rebuilt state transaction locally, sending only the minimal 005 credential
(`payment_authorization_id` plus buyer transaction signature).
