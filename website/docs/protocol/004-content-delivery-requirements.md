---
id: 004-content-delivery-requirements
title: "004 · Content Delivery Proof Requirements"
---

# 004 · Content Delivery Proof Requirements

## Problem Statement

After receiving 003, the seller must deliver the ordered payload batch atomically: one delivery package carries the payloads for the entire authorized hash batch, all-or-nothing. The delivery MUST NOT echo back the quote, fee pool, hashes, or request parameters item by item; it only needs to unambiguously answer "which buyer authorization this delivery corresponds to, and what the exact bytes being delivered are."

## Minimal Delivery Relationship

004 is wire Kind 6: a five-element shell whose seller signature covers the
exact `content_delivery_cbor` through `SignWireDocument(1, 6, ...)`. The
signed document carries only the `PaymentAuthorizationID`, and the payload
batch travels as an attachment. It carries no pool ID and no content hashes —
both are recovered from the saved original 003 that the application locates by
the authorization ID. A 004 arriving without a locally saved 003 is parked or
dead-lettered (or the peer is asked to resend 003); receivers never guess the
order or fee pool from payloads or connection state.

```text
BuyerSignature -> payment_authorization_cbor (SignWireDocument(1, 5, ...))
payment_authorization_cbor -> ordered content_hashes_cbor + pool + sequence + amount
PaymentAuthorizationID = SHA-256(payment_authorization_cbor)
content_delivery_cbor = deterministic-CBOR([payment_authorization_id])
SellerSignature -> content_delivery_cbor   (SignWireDocument(1, 6, ...))
ContentPayloadsCBOR[i] -> SHA-256 -> ContentHashesCBOR[i]
```

Because payloads are not directly signed, acceptance MUST verify every item: count strictly equal to the hash count, order preserved, per-item SHA-256 equal to the committed hash, seed/block membership, protocol expected lengths, and the recomputed aggregate price against the absolute cumulative amount. Any single failure rejects the whole batch — no partial payment, no zero-priced missing items, no prefix acceptance.

The seller signs the exact `content_delivery_cbor` through the unified `SignWireDocument(1, 6, ...)` helper (one internal SHA-256 over the typed signing input, low-S DER); the typed input authenticates version and kind together with the exact document. Signatures over a bare hash, hex text, payloads, or pre-hashed digests are not this protocol.

## Delivery Deadline Boundary

`DeliveryDeadlineUnix` comes from 003. The buyer decides whether to accept based on the local time read once when the delivery is verified; a timestamp filled in by the seller cannot prove when the content was delivered over the network, therefore the protocol does not treat seller-declared time as objective evidence. 004 itself carries no time fields.

The seller's signature proves that the seller committed to this authorization and supplied verifiable payloads; it cannot independently prove that the buyer actually received them before the deadline. The buyer's signature on the payment state in 005 constitutes strong evidence of acceptance and payment. If arbitration later needs to determine "whether the seller delivered on time and the buyer refused to pay," a provable receipt mechanism MUST be introduced separately. The 007 Claim does carry the exact seller-validated payload bundle as custody evidence, but it still does not adjudicate network delivery time or prove buyer receipt.

For encoding details, see the [Content Delivery Proof Specification](/docs/protocol/004-content-delivery-spec).
