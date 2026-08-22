---
id: 003-content-request-requirements
title: "003 · Content Retrieval Request Requirements"
---

# 003 · Content Retrieval Request Requirements

## What Problem This Solves

Once the buyer has selected a quote and has an available fee pool, the buyer needs to send the seller a final payment authorization saying "please deliver this ordered batch of content." One payment sequence authorizes one group of content hashes; prices are derived item by item and safely accumulated. The request must enable the seller to verify: which quote the buyer selected, which fee pool is being used, which target payment state the authorization applies to, what content is requested, and the delivery deadline.

This is not 005 transaction signing, but it already commits the absolute cumulative seller amount and the target sequence number that must be executed after the buyer inspects the delivery; the buyer has not yet inspected the content, and the fee pool amount has not yet advanced. The whole batch succeeds or fails atomically: there is no partial delivery, partial payment, or prefix acceptance.

## How Content Is Addressed

003 carries an ordered batch of 1–64 unique 32-byte content hashes (`ContentHashesCBOR`, a deterministic CBOR child document embedded as `bstr`). There is no sender-declared content type:

- A hash equal to the quote's `SeedHash` is recognized as the seed, priced at `SeedPriceSat`.
- Every other hash MUST be found in that seed's block hash list, priced at its position's protocol expected length (full blocks at `FullBlockPriceSat`; tail blocks with the proportional round-up and 10% seller calculation rule).
- A hash found nowhere returns `ErrContentNotInSeed`.
- Order is part of the authorization: hashes are never sorted, deduplicated, or reordered before acceptance. Duplicate entries are rejected outright.
- If the same hash occurs at multiple seed positions, it is purchased once and reused for every identical position in file reconstruction. If those positions imply conflicting expected lengths, the evidence is ambiguous and the whole request is rejected.
- When the batch includes any block, the buyer MUST already hold a verified seed whose hash equals the quote's `SeedHash`. Mixed seed+block batches are allowed only under that condition; buyers who do not have the seed purchase it alone first.

## How the Fee Pool Is Addressed

The buyer selects an available pool by `RefundTemplateTxID` and commits to a single target `PaymentSequence`: receivers verify `request.PaymentSequence == previous.PaymentSequence + 1` against their current accepted state, and the target never exceeds `0xfffffffe`.

`SellerAmountAfterSat` is the seller's absolute cumulative amount after the batch payment — never a per-batch increment. The aggregate batch price must equal exactly `SellerAmountAfterSat - previous.SellerAmountSat`, accumulated with checked addition before signing; overflow, insufficient capacity, or any single item failing classification fails the whole construction before any signature exists.

The same pool MUST NOT be accepted by the seller for multiple outstanding requests simultaneously; otherwise the same balance would be committed multiple times. This is a local operational constraint on the calling application (serialize batches per pool); the SDK validates only explicit inputs and adds no stores, mutexes, or leases.

In 003, the buyer commits to the target sequence number and absolute cumulative amount; the seller is not required to countersign or acknowledge these fields. The seller may deliver per 004, or may refuse or take no action; if the seller cannot deliver normally and the buyer declines to sign 005, the seller may use this final authorization for arbitration per 007.

## Why Only References Are Carried

The request carries no public keys and no miner fee rate: Buyer/Seller/Arbiter keys and the fee rate are uniquely determined by the immutable OpeningProof behind `RefundTemplateTxID`. Any cryptographic verification therefore requires the corresponding OpeningProof (`VerifySignedContentRequestForOpening`); 007 already carries one and uses this path. The quote is selected by `QuoteTermsHash` alone — the fee pool cannot replace the quote, because the same pool can buy different quotes for the same roles.

The exact `TermsCBOR` then produces `PaymentAuthorizationHash = SHA-256(TermsCBOR)`. 004 uses it to reference the authorization, 005 uses it to associate payment with a specific batch pickup, and 007 submits only the complete 003 authorization along with fee pool execution material — the arbitrator is not required to read 001, 004, payloads, or the historical payment chain.

For encoding details, see [Content Retrieval Request Specification](003-content-request-spec.md).
