---
id: 006-pool-close-requirements
title: "006 · Fee Pool Close Requirements"
---

# 006 · Fee Pool Close Requirements

## Problem Statement

The buyer has not committed to purchasing any specific amount of content and may purchase none at all. Therefore, the buyer is not required to request closure from the seller, nor can the buyer sue the seller for inaction; the buyer simply waits for the fee pool to expire and submits the refund transaction already obtained in 002. Closure is not an occasion to re-argue quotes, files, or delivery.

## Stakeholder Interests

If the seller submits no cumulative payment transactions, the buyer obtains a full refund upon expiry. Each time the seller uses and submits a cumulative payment state checked out by the buyer, the transaction itself settles both the seller's cumulative amount and the buyer's change upon expiry. The seller initiates an arbitration submission only when the seller wishes to assert a payment state that the buyer has checked out but that the seller cannot submit normally. Arbitration typically incurs a cost, so it serves as the seller's last resort, not a tool for the buyer to expedite closure.

## BitFS v4 Scope

Arbitration submissions in BitFS v4 execute only the final payment authorization and independently rebuilt state that are verifiable:

- Does not re-adjudicate whether a file has been delivered;
- Does not compensate, penalize, or recalculate amounts for either party;
- Never deducts the arbitration service fee silently: the fee is an explicit, positive `output[2]` allocation that the Receipt binds and the Seller verifies before co-signing;
- Does not support the buyer making closure or amount requests to the arbiter.

The miner fee for the buyer's refund upon expiry is covered by the existing rules of the refund transaction. Since the 007 paid-arbitration hard switch, the arbiter's commercial service fee is allocated from the pool's spendable balance as the explicit positive `ArbiterAmountSat` in `output[2]`: the Buyer amount absorbs it (`Buyer + Seller + Arbiter + refund fee = pool output`), the Seller amount stays exactly the Buyer-signed absolute `SellerAmountAfterSat`, and paying the arbiter outside the pool or adding submission inputs is not part of the protocol.

## Evidence Requirements for the Arbiter

The arbiter is not an original participant and cannot trust state from a mere transaction ID or session identifier. All arbitration evidence must be bound to the fee pool's `RefundTemplateTxID` correlation ID, which is derived from the Claim's canonical `refund_template_raw`. When the seller initiates an arbitration submission, the seller MUST provide the exact source amount and locking script, refund template, Buyer-signed 003 terms, Seller Claim signature, and the validated 004 payload bundle. The seller MUST NOT require the buyer to sign 005 for this dispute, and MUST NOT include OpeningProof, FundingTx, fee rate, previous state, candidate raw bytes, or Seller transaction signature on the wire. The arbiter independently validates the payload custody evidence, rebuilds the paid candidate through the same deterministic pool builder with its explicitly decided positive fee, signs the arbitration transaction first, then places the Claim ID, that fee, and the transaction signature into the Receipt and signs `[4, 9, exact_receipt_cbor]`. Full requirements are specified in 007.

For the specific close messages and the unsettled boundaries of BitFS v4, see [Fee Pool Unconditional Close Specification](006-unconditional-pool-close-spec.md).
