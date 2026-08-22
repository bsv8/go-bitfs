---
id: 004-content-delivery-requirements
title: "004 · Content Delivery Proof Requirements"
---

# 004 · Content Delivery Proof Requirements

## Problem Statement

After receiving 003, the seller must deliver the ordered payload batch atomically: one delivery package carries the payloads for the entire authorized hash batch, all-or-nothing. The delivery MUST NOT echo back the quote, fee pool, hashes, or request parameters item by item; it only needs to unambiguously answer "which buyer authorization this delivery corresponds to, and what the exact bytes being delivered are."

## Minimal Delivery Relationship

004 is a four-element shell carrying only `PaymentAuthorizationHash`, the seller's signature over that exact 32-byte hash, and the ordered payload batch. It carries no pool ID and no content hashes — both are recovered from the saved original 003 that the application locates by the authorization hash. A 004 arriving without a locally saved 003 is parked or dead-lettered (or the peer is asked to resend 003); receivers never guess the order or fee pool from payloads or connection state.

```text
BuyerSignature -> 003 TermsCBOR
003 TermsCBOR -> ordered ContentHashesCBOR + pool + sequence + amount
PaymentAuthorizationHash = SHA-256(003 TermsCBOR)
SellerSignature -> PaymentAuthorizationHash   (bare message signing)
ContentPayloadsCBOR[i] -> SHA-256 -> ContentHashesCBOR[i]
```

Because payloads are not directly signed, acceptance MUST verify every item: count strictly equal to the hash count, order preserved, per-item SHA-256 equal to the committed hash, seed/block membership, protocol expected lengths, and the recomputed aggregate price against the absolute cumulative amount. Any single failure rejects the whole batch — no partial payment, no zero-priced missing items, no prefix acceptance.

The seller signs the bare 32-byte hash through the fixed `SignMessage` path (one internal SHA-256, low-S DER). The shell version does not enter the signature; signatures over `[4, hash]` CBOR wrappers, hex text, payloads, or pre-hashed digests are not this protocol.

## Delivery Deadline Boundary

`DeliveryDeadlineUnix` comes from 003. The buyer decides whether to accept based on the local time read once when the delivery is verified; a timestamp filled in by the seller cannot prove when the content was delivered over the network, therefore v4 does not treat seller-declared time as objective evidence. 004 itself carries no time fields.

The seller's signature proves that the seller committed to this authorization and supplied verifiable payloads; it cannot independently prove that the buyer actually received them before the deadline. The buyer's signature on the payment state in 005 constitutes strong evidence of acceptance and payment. If arbitration later needs to determine "whether the seller delivered on time and the buyer refused to pay," a provable receipt mechanism MUST be introduced separately; 007 does not adjudicate network delivery times.

For encoding details, see the [Content Delivery Proof Specification](/docs/protocol/004-content-delivery-spec).
