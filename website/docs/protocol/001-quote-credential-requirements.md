---
id: 001-quote-credential-requirements
title: 001 · Quote Credential Requirements
---

# 001 · Quote Credential Requirements

## Problem Statement

A seller needs to commit to a specific buyer: how a file corresponding to a given seed can be sold, the price per seed, the price per complete block, which arbitrators are acceptable, and when the quote expires.

The most critical requirement here is not "being able to look up a quote in a database," but rather that anyone who holds the quote data and the seller's signature can independently verify that the quote was made by that seller. The ground truth of a quote is the terms data and the signature; the database merely helps both parties store and locate it.

## Aligned Business Rules

- A quote targets exactly one buyer public key; BitFS v3 does not support open multi-buyer quotes.
- Quotes have no effective time, only an expiration time.
- Quotes provide only the seed price and the complete-block price; the final partial block is calculated from the actual file size derived from the file seed, and the seller should grant the buyer a 10% margin for calculation tolerance.
- The recommended filename is only a display suggestion after download; it is not the basis for file identity, pricing, or fulfillment.
- The arbitrator list represents candidates accepted by the seller; the buyer selects one from this list at the time of purchase.

## Why Not Use a Quote ID

A manually assigned quote ID would bind the protocol to a specific server or database. Instead, `QuoteTermsHash = SHA256(FileQuoteTermsCBOR)` is used: it is a fingerprint of the terms content, not a row record created by someone.

Routine buy-sell messages carry only this hash to avoid redundant transmission; when migration, auditing, or arbitration is needed, both parties can present the original quote credential for verification. Even if a seller has multiple quotes, this hash allows precise retrieval of the one selected by the buyer.

## Implications for Subsequent Steps

003 does not repeat the original quote text, file size, buyer/seller public keys, or prices; it references only `QuoteTermsHash`. The seller recovers this information from the verified quote. The complete quote credential must be retained by both parties until the associated payment is settled and the arbitration window has closed.

For specific fields, CBOR layout, and the Go API, see the [Quote Credential Specification](001-quote-credential-spec.md).
