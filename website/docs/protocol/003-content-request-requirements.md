---
id: 003-content-request-requirements
title: "003 · Content Retrieval Request Requirements"
---

# 003 · Content Retrieval Request Requirements

## What Problem This Solves

Once the buyer has selected a quote and has an available fee pool, the buyer needs to send a request to the seller saying "please deliver this specific content." The request must enable the seller to verify: which quote the buyer selected, which pool's current payment capacity is being used, which arbitrator was chosen, whether a seed or a specific block is requested, and the delivery deadline.

This is not 005 transaction signing, but it already commits the final cumulative amount and target sequence number that must be executed after the buyer inspects the delivery; the buyer has not yet inspected the content, and the fee pool amount has not yet advanced.

## How Content Is Addressed

There are only two types of content requests:

- `Seed`: Request the seed corresponding to the quote; the content hash MUST equal the `SeedHash` in the quote.
- `Block`: Request a file block; the content hash MUST exist in the block hash list provided by the already-obtained seed.

The seed contains the file block hash list, so the block index, actual block size, and tail-block identity can all be derived from the seed. The request does not redundantly send the block index or size. Blocks may be requested in any order; "obtain the seed first" is a content-discovery convention, not a payment-sequence implication.

## How the Fee Pool Is Addressed

The buyer selects an available pool and its current latest cumulative payment state:

```text
SpendTxID + BasePaymentSequence
```

`BasePaymentSequence` is the fee pool state version — it is not a block sequence number, not a request sequence number, and does not encode any ordering between seeds and blocks. The buyer may select any one of their available pools but MUST use that pool's current latest state.

The same pool MUST NOT be accepted by the seller for multiple outstanding requests simultaneously; otherwise the same balance would be committed multiple times, and the buyer could pay only once after the seller delivers several contents. This is a local operational constraint on the seller; it does not turn the database into the source of truth — the seller's saved signed payment state is the authoritative record. The specific atomic latch, persistence, and release timing are defined in 005.

In 003, the buyer commits to the sequence number, absolute cumulative amount, and fixed fee rate; the seller is not required to countersign or acknowledge these fields. The seller may deliver per 004, or may refuse or take no action; if the seller cannot submit normally and the buyer declines to sign 005, the seller may use this final authorization request for arbitration per 007.

## Why Only a Reference Is Carried

The request carries `QuoteTermsHash` rather than repeating the full quote text. This hash enables the seller to precisely locate the selected terms among multiple quotes; the seller verifies the original quote and its signature before it can verify the buyer's request signature.

The request itself then produces `PaymentAuthorizationHash`. 004 uses it to reference the authorization, 005 uses it to associate payment with a specific pickup, and 007 submits only the complete 003 authorization along with fee pool execution material — the arbitrator is not required to read 001, 004, the payload, or the historical payment chain.

For specific fields and validation rules, see [Content Retrieval Request Specification](003-content-request-spec.md).
