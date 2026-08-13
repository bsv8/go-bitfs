---
id: 006-pool-close-requirements
title: "006 · Fee Pool Close Requirements"
---

# 006 · Fee Pool Close Requirements

## Problem Statement

The buyer has not committed to purchasing any specific amount of content and may purchase none at all. Therefore, the buyer is not required to request closure from the seller, nor can the buyer sue the seller for inaction; the buyer simply waits for the fee pool to expire and submits the refund transaction already obtained in 002. Closure is not an occasion to re-argue quotes, files, or delivery.

## Stakeholder Interests

If the seller submits no cumulative payment transactions, the buyer obtains a full refund upon expiry. Each time the seller uses and submits a cumulative payment state checked out by the buyer, the transaction itself settles both the seller's cumulative amount and the buyer's change upon expiry. The seller initiates an arbitration submission only when the seller wishes to assert a payment state that the buyer has checked out but that the seller cannot submit normally. Arbitration typically incurs a cost, so it serves as the seller's last resort, not a tool for the buyer to expedite closure.

## BitFS v3 Scope

Arbitration submissions in BitFS v3 execute only the final payment authorization and candidate state provided by the seller that are verifiable:

- Does not re-adjudicate whether a file has been delivered;
- Does not compensate, penalize, or recalculate amounts for either party;
- Does not silently deduct arbitration service fees from the pool;
- Does not support the buyer making closure or amount requests to the arbiter.

The miner fee for the buyer's refund upon expiry is covered by the existing rules of the refund transaction. The arbiter's commercial service fee in BitFS v3 is paid by the seller out-of-pool or covered by the seller providing additional inputs for the submission transaction; if it must be deducted from the pool, it falls under arbitration amount design and must be specified separately.

## Evidence Requirements for the Arbiter

The arbiter is not an original participant and cannot trust state from a mere transaction ID. When the seller initiates an arbitration submission, the seller MUST provide the complete pool-opening proof, the buyer's checked-out final payment authorization, the empty-unlock candidate transaction constructed by the seller based on the authorization, and the Seller detached signature; the seller MUST NOT require the buyer to sign 005 for this dispute, and MUST NOT include 001, 004, the payload, or the historical payment chain as business evidence. The arbiter only verifies the candidate transaction and signs with an Arbiter detached signature, and MUST NOT create a new amount ground truth for the seller's missing counter-signature. Full requirements are specified in 007.

For the specific close messages and the unsettled boundaries of BitFS v3, see [Fee Pool Unconditional Close Specification](006-unconditional-pool-close-spec.md).
