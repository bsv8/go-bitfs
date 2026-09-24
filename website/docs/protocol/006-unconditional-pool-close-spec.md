---
id: 006-unconditional-pool-close-spec
title: 006 · Negotiated immediate-close specification
---

# 006 · Negotiated immediate-close specification

The pool lifecycle wire definitions belong to [002 · Fee Pool Opening and Closing Specification](002-pool-opening-spec.md), alongside the opening messages that establish `RefundTemplateTxID`. That specification defines the exact Kind 12 and Kind 13 arrays. This page specifies close transaction behavior and validation boundaries.

MultisigPool v4 performs immediate close by constructing an unsigned three-output state with the final sequence and locktime; the Arbiter output remains present with amount 0. The buyer signs that exact unsigned transaction. The seller validates the request, adds its signature, and returns the complete final transaction. Local accepted state MUST NOT advance before the node confirms the transaction.

### Wire exchange

The buyer sends the exact Kind 12 request defined in 002. It contains the pool ID first, then the unsigned final-close transaction and the buyer's detached transaction signature. The seller compares the ID with its opening evidence, validates and signs the candidate, then returns the exact Kind 13 response. The buyer checks the repeated pool ID and fully verifies the complete transaction.

The two Artifacts define the BitFS messages. Transport, persistence, retry policy, node submission, and confirmation tracking remain application responsibilities. The node submission interface uses the complete raw transaction and its real on-chain txid; `RefundTemplateTxID` remains a pool correlation ID and never impersonates that txid.
