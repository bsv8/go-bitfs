---
id: 004-content-delivery-requirements
title: "004 · Content Delivery Proof Requirements"
---

# 004 · Content Delivery Proof Requirements

## Problem Statement

After receiving 003, the seller must deliver the seed body or file-chunk body. The delivery MUST NOT echo back the quote, fee pool, arbiter, and request parameters item by item; it only needs to unambiguously answer "which buyer request this delivery corresponds to, and what the exact bytes being delivered are."

## Minimal Delivery Relationship

004 references `PaymentAuthorizationHash` together with the content bytes. The seller signs the deterministic CBOR encoding of these two items. The buyer reconstructs all purchase conditions from the 003 it stored locally, verifies the seller identity, content hash, and delivery deadline; only upon passing these checks does payment proceed.

```text
003: Buyer deterministically requests specific content with a signature
004: Seller deterministically delivers specific bytes with a signature
005: Buyer advances the cumulative payment state upon acceptance
```

## Delivery Deadline Boundary

`DeliveryDeadlineUnix` comes from 003. The buyer SHOULD decide whether to accept based on the local time at which the delivery package is actually received and verified; a timestamp filled in by the seller cannot prove when the content was delivered over the network, therefore v4 does not treat the seller-declared time as objective evidence.

The seller's 004 signature proves that the seller declared and committed to these content bytes, but it cannot independently prove that the buyer actually received them. The buyer's signature on the payment state in 005 constitutes strong evidence of acceptance and payment. If arbitration later needs to determine "whether the seller delivered on time and the buyer refused to pay," a provable receipt or arbitrated handoff mechanism MUST be introduced separately.

For specific fields and validation rules, see the [Content Delivery Proof Specification](/docs/protocol/004-content-delivery-spec).
