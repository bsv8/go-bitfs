---
id: 002-pool-opening-requirements
title: "002 · Fee Pool Opening Requirements"
---

# 002 · Fee Pool Opening Requirements

## Problem Statement

The buyer needs to prepare a 2-of-3 fee pool that can accumulate subsequent payments, but must not have funds permanently locked if the seller refuses to sign later transactions. Pool opening is independent of BitFS file purchase: it MUST NOT be aware of quotes, seeds, file chunks, or pricing.

## Sequence Driven by Stakeholder Incentives

The buyer first constructs the funding transaction and the time-lock refund transaction locally. The seller signs the refund transaction first; at this point the funding transaction has not been broadcast, so the seller's signature does not risk their own funds. Only after the buyer obtains and verifies the seller's signature does the buyer hand the funding transaction to the seller for submission.

```text
Buyer obtains refund guarantee → then hands over funding transaction → seller verifies and submits funding transaction
```

Success on the buyer side is "has obtained and persisted a verifiable refund signature from the seller"; success on the seller side is "the funding transaction submission interface returned successfully." Pool opening does NOT wait for on-chain confirmation.

## Ground Truth and Persistence

Each party — buyer and seller — persists the transactions, source output descriptions, and both parties' signatures. The persistence medium may be a database, file, or browser storage, but these are merely evidence repositories; the original transactions and signatures are the ground truth. The SDK collaborates with external systems through capability interfaces for storage, signing, signature verification, transaction ID calculation, and transaction submission; it does NOT own the server side.

## Implications for Subsequent Steps

Pool opening produces a stable `SpendTxID` that serves as the fee pool anchor. From spec 003 onward, the funding transaction and refund transaction are NOT re-transmitted; instead, the current cumulative payment sequence number combined with `SpendTxID` references the persisted pool state.

For the detailed transaction sequence, messages, and SDK hooks, see [Fee Pool Opening Specification](002-pool-opening-spec.md).
