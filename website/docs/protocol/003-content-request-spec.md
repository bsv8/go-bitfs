---
id: 003-content-request-spec
title: 003 · v4 Content Request Specification
---

# 003 · v4 Content Request Specification

The business fields of 003 retain the original semantics for quote, content, and delivery deadline, with encoding major version 4. The final authorization is permanently bound to the pool `SpendTxID`, base/target sequence, Seller absolute cumulative amount, integer rate, and Buyer/Seller/Arbiter public keys.

The authorization hash serves as the `PaymentAuthorizationHash` for subsequent 004, 005, and 007. The current version does not carry a negotiable arbitration amount; the construction layer always uses `ArbiterAmount = 0`.
