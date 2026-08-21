---
id: 007-seller-arbitration-submission-requirements
title: 007 · Seller arbitration submission requirements
---

# 007 · Seller arbitration submission requirements

## Problem statement

When a seller holds buyer-signed final payment authorization from 003 but the buyer has not signed the corresponding 005, or the normal path cannot complete, an arbiter can supply the second signature for a `Seller+Arbiter` 2-of-3 spend. The arbiter is not a replica of either party's database and cannot receive only a hash or `SpendTxID` and then query a participant for the missing material.

The seller MUST submit complete raw credentials and raw signatures.

## What the arbiter does

The arbiter does not decide again whether a file block was delivered or recalculate the quote or amount due. By signing the final authorization in 003, the buyer has already committed to the target payment sequence, absolute cumulative seller amount, pool roles, and fee rate.

The arbiter checks that this state is executable and then signs that exact transaction.

```text
Not: the arbiter decides that the seller should receive X
But: the buyer authorized X, and the arbiter checks the seller's candidate and adds an Arbiter detached signature
```

## Why the complete business history is unnecessary

An arbitration submission cannot contain only hash references and cannot require the buyer to sign 005 first. The minimum evidence is:

```text
Complete pool opening proof
+ final 003 payment authorization
+ seller-constructed candidate transaction with an empty unlocking script
+ Seller detached signature
```

The arbiter verifies only the 003 authorization, candidate transaction, and seller signature. It does not read 001, 004, the payload, or historical payment states, and it neither constructs nor modifies the transaction. The response contains only the authorization hash, candidate transaction hash, and Arbiter detached signature.

## One-way boundary

Only a seller can initiate this step. A buyer cannot request arbitration close because a seller failed to submit a transaction, countersign an amount, or respond; the buyer waits for expiry and receives its refund or change. The seller pays the arbitration service cost, and BitFS v4 does not silently deduct it from the pool.

See the [Seller arbitration submission specification](007-seller-arbitration-submission-spec.md) for the evidence package and validation rules.
