---
id: 005-cumulative-payment-requirements
title: 005 · Cumulative Payment Requirements
---

# 005 · Cumulative Payment Requirements

## Problem Statement

The buyer verifies the 004 content before checking out the cumulative payment state and handing it to the seller. The fee pool does not deduct a temporary amount independently per block; instead it uses an overwriting cumulative payment state: the same pool always spends the same base output, and the latest state fully carries forward all previously paid amounts.

The seller submits the forward transaction to the BSV finality-deferred transaction pool. Before expiry it is only validated, stored, and overwritten by nodes—it does not enter a block; after expiry the latest state becomes eligible for inclusion. If both parties agree to close the pool, they mark the same state as immediately finalized and submit it.

## Most Important Rule: Payment Sequence

`PaymentSequence` is the `nSequence` of the spending transaction input. It describes the fee pool version, not a file block number or request number, and does not express the ordering between seed and blocks.

Let the current latest state be `N` and the seller's cumulative receivable amount be `S`. A normal payment produces a sequence number that is greater than `N` but less than `0xffffffff`; the seller's cumulative receivable amount becomes `S + this payment amount`.

```text
State 7: seller cumulative receivable 1,000 sat
This payment: 80 sat
State 8 or State 20: seller cumulative receivable 1,080 sat
```

Skipping sequence numbers does not change the amount rules, nor is it permissible to generate two different states with the same or a smaller sequence number. `0xffffffff` is reserved exclusively for voluntary closure and must not be used for normal content payments.

After the buyer checks out the payment transaction, the seller does not need to send an application-layer counter-signature message such as "I confirm this amount." The transaction signature and the finality-deferred pool acceptance result are themselves verifiable facts.

## File Blocks, Fee Pools, and Serial Requests

The seed is first used to discover the list of file block hashes; after that, file blocks may be purchased in any order by any hash. Different blocks of the same file may use different fee pools; the same fee pool may also pay for any file block, provided it belongs to a valid fee pool composed of the same buyer, seller, and selected arbitrator.

However, the same pool at a given current sequence number may have at most one pending content request. Otherwise, the buyer could use the same balance to request multiple blocks simultaneously; after the seller delivers, the buyer could check out only one payment, resulting in free content delivery.

Therefore, in BitFS v4 the seller's behavior is:

1. Upon receiving 003, verify the authorization against its OpeningProof and the fee pool's current latest accepted state (target `PaymentSequence` = current + 1, absolute cumulative amount), and confirm that no in-progress request exists in the pool.
2. Atomically save the in-progress request together with the exact signed 003 indexed by its `PaymentAuthorizationHash`, then deliver 004.
3. Upon receiving the minimal 005 (authorization hash plus buyer transaction signature), look up the exact original saved 003 under that hash — a hash is a lookup key and can never be decoded into a pool ID, amount, or transaction — then cross-compare it with the locally saved ContentDeliveryState, the OpeningProof-derived `RefundTemplateTxID`, and the previous PaymentState; rebuild the unsigned payment state transaction locally through the single `BuildPaymentUpdate` implementation; verify the detached buyer signature over that exact rebuilt transaction; then co-sign and merge. Whether the seller accepts a 005 whose base state is still its current business-latest record, and when the application may spend or forward the merged payment, are application decisions: the SDK verifies the candidate against the explicitly supplied evidence only.
If the hash cannot be resolved to an original 003, if the delivery context does not match (wrong pool, stale sequence, or duplicate), or if the rebuilt bytes differ from anything previously reconstructed for this authorization, reject the 005; never ask the buyer to resend an old wire raw transaction as a fallback. The authorization hash is only a lookup key into the saved 003: one pool can hold many different authorization hashes at the same time, so locking by hash cannot stop two requests from consuming the same previous state. All 003 acceptance, 004 delivery, and 005 merging MUST be serialized per pool, keyed by the `RefundTemplateTxID` recovered from the looked-up 003 (unique key, transaction, row lock, or single queue — the SDK has no lock). Parallel purchases require separate fee pools.

This delivery-context record is the seller's delivery-risk control data and is persisted by the calling application in its own storage; the SDK neither saves it nor exposes any hook. It is not the source of truth for the fee pool or payment and must not be used to tamper with signed transactions.

## Expiry and Risk Boundary

This is a one-way risk boundary: if the seller does not submit any payment transaction, the buyer walks away with a full initial refund after expiry; if the seller submits the latest cumulative payment transaction, the transaction settles after expiry according to its cumulative amount with the buyer receiving change. The buyer does not sue the arbitrator because of the seller's inaction, nor does the buyer need the seller to counter-sign an off-chain "amount confirmation."

Only when the seller is unable to normally submit a payment transaction that the buyer has checked out may the seller request the arbitrator to supply the missing signature per 007. The arbitrator verifies the complete pool-opening proof and the exact payment transaction—not database records, individual amount fields, or textual payment sequence numbers.

## Why This Works

An ordinary Bitcoin sequence number is not an on-chain "higher wins" rule by itself; this design relies on the BSV node's finality-deferred transaction pool: forward transactions for the same input overwrite older states with a higher `nSequence`, and enter an includable state only after expiry. Consequently, the 005 implementation must use a node submission interface that supports this capability and must not treat an ordinary broadcast node as a fee pool state machine.

For the specific CBOR fields, transaction validation, and hook boundaries, see [Cumulative Payment Specification](005-cumulative-payment-spec.md).
