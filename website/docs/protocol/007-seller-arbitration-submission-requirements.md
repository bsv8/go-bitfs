---
id: 007-seller-arbitration-submission-requirements
title: 007 · Seller arbitration submission requirements
---

# 007 · Seller arbitration submission requirements

007 is the custody-and-settlement exception for a Buyer-signed 003 whose
normal 004/005 path cannot complete. The Seller submits the exact content
payloads and signs a Claim. The Arbiter verifies and holds those bytes,
decides a positive arbitration fee, builds the paid payment independently, and
signs only after the application confirms persistence.

## Required evidence

The Seller MUST send exactly the five-element Kind 8 request. Its Claim
contains only:

- the claimed pool output satoshis and exact role-ordered P2MS locking script;
- the canonical unsigned RefundTx raw bytes;
- the exact Buyer-signed 003 payment authorization document and Buyer signature.

The outer request separately carries the Seller message signature
`SignWireDocument(1, 8, exact_claim_cbor)` and the canonical 1–64 item
`content_payloads_cbor`.
It MUST NOT contain OpeningProof, FundingTx, fee rate, previous state,
candidate raw bytes, `RefundTemplateTxID` as a duplicate field, or a Seller
transaction signature. It MUST NOT carry an arbitration fee: the fee is only
decided after the Arbiter has received and verified the payloads.

The Claim locking script fixes the role order `[Buyer, Seller, Arbiter]`.
The SDK validates the Buyer signature, RefundTx ID against the terms, output
shape, source arithmetic, payload count/order/size/hash, and all canonical
CBOR. It does not claim to validate on-chain UTXO existence, confirmation, or
unspent status; a wrong Seller source context is recorded by the application
as an unspendable-source reconciliation failure.

## Arbiter boundary

The application MUST complete the on-chain UTXO pre-check before pricing and
signing. The SDK never queries a node; the production service must verify that
the Claim's outpoint exists, its amount matches the Claim, its script matches
the pool locking script, and it is confirmed and unspent. A failed, timed-out,
or uncertain UTXO lookup MUST reject signing — uncertainty is never treated as
spendable, and no degraded or free response may be produced.

The application MUST compute the positive `arbiter_amount_sat` with its own
fee policy over exactly `len(ContentPayloadsCBOR)` (integer formulas only),
then persist the exact inbound request, payload bundle, derived Claim ID, and
frozen fee before requesting any signature:

```text
raw Kind 8 received -> strict decode -> evidence verification
  -> application verifies the on-chain UTXO
  -> application prices the fee
  -> arbiter.PrepareArbitration(facts, rawKind8, arbiterAmountSatoshis)
  -> atomic custody persistence (append-only: request, payload, Claim ID,
     fee stay immutable once written)
  -> arbiter.SignPreparedArbitration(ctx, facts, prepared, signer)
  -> persist/send exact Kind 9
```

A zero fee fails as invalid evidence before anything is persisted or signed.
An amount that cannot fit after the Buyer-authorized Seller amount fails with
the `CodeInsufficientBalance` error category; there is no free or partially-paid fallback.

`arbiter.PrepareArbitration` has no transaction-signing side effect. It returns
plain `PreparedArbitrationEvidence` data: the exact Kind 8 bytes, the
independently rebuilt unsigned candidate, the Claim ID, and the frozen fee.
The application persists that plain evidence and passes it back to
`arbiter.SignPreparedArbitration`, which revalidates every field from the
exact Kind 8 bytes before any signer is reached. Custody records are
append-only: after signing, the exact canonical Kind 9 bytes are attached to
the same record without overwriting the request, payload, Claim ID, or fee.

The Receipt binds the Claim ID, the absolute arbiter amount, and the exact
`ForkID|All` transaction signature under the ordinary message signature
`SignWireDocument(1, 9, exact_receipt_cbor)`. The Receipt message signature and the
transaction signature are separate credentials; neither can substitute for the
other.

Replay is keyed by the Claim ID but gated on exact bytes. After
strict-decoding an inbound Kind 8 and deriving its Claim ID:

1. Identical Claim ID and identical exact Kind 8 bytes replay the persisted
   response verbatim without re-pricing or re-signing;
2. the same Claim ID with different exact Claim bytes is a hash-collision
   alarm that stops automation without overwriting records;
3. the same exact Claim but a different outer Seller signature or payload
   bundle must first be fully re-validated with the frozen fee via
   arbiter.PrepareArbitration — validation failure rejects the input as invalid evidence
   and never raises a collision alarm, while a fully valid variant is recorded
   as a duplicate-evidence conflict that stops automation;
4. a different Claim ID creates an independent custody record.

## Seller completion

The Seller MUST rebuild the same paid candidate from the Claim primitives plus
the receipt's arbiter amount after receiving Kind 9. It recomputes the Claim
ID from its own Claim bytes, verifies the Claim, Buyer terms signature,
Receipt message signature (with the Arbiter key recovered from the role-ordered
pool script), and Arbiter transaction signature before creating its own
transaction signature. It then merges only through
`MergeArbitratedPoolSellerArbiterSignatures`. Broadcasting, reconciliation,
retention, and idempotency are application responsibilities. Buyer retrieval
wire and signatures are fixed by the SDK through step 008 (Kind 10/11); the
application still owns persistence, nonce deduplication, TLS transport, and
retention. Any tampering with the Claim ID, fee, transaction signature,
or receipt signature rejects the whole response.
