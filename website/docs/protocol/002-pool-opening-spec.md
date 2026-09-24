---
id: 002-pool-opening-spec
title: "002 · Fee Pool Opening and Closing Specification"
---

# 002 · Fee Pool Opening and Closing Specification

The Buyer creates a pool lock using `ArbitratedPoolRoles{Buyer, Seller, Arbiter}` from MultisigPool v4. The public key order is fixed as `[Buyer, Seller, Arbiter]`.

The opening/refund state MUST contain exactly three funding outputs: Buyer, Seller, and Arbiter. The Seller and Arbiter initial amounts are 0; the Arbiter output MUST still be present. The opening sequence is returned by the MultisigPool dependency and is currently 2; go-bitfs MUST NOT rewrite the sequence, locktime, fee, or script.

The Buyer produces a detached Buyer signature over the unsigned RefundTx, and the Seller produces a detached Seller signature over the same unsigned transaction. Both parties MUST persist the complete OpeningProof before delivering or broadcasting the FundingTx. Time-based refunds MUST be merged exclusively via `MergeArbitratedPoolBuyerSellerSignatures`.

The pool output in FundingTx MUST be output index 0. RefundTx carries that outpoint directly. RefundTemplateTxID is the canonical transaction ID of the unsigned RefundTx and is the unified pool correlation ID; FundingTxID is read from its input. The pool amount is derived from RefundTx's Buyer output plus the canonical MultisigPool fee, and the pool locking script is derived from the ordered participant keys. These values MUST NOT be duplicated in either the presign request or OpeningProof.

Kind 2 RefundPresignRequest is a fixed seven-element wire array `[1, 2, refund_template_raw, buyer_public_key, seller_public_key, arbiter_public_key, miner_fee_rate_satoshis_per_kilobyte, buyer_refund_transaction_signature]` under `protocol.WireVersion = 1`. The wire version uniquely selects the MultisigPool transaction rules, so separate discriminators are forbidden.

The locally persisted OpeningProof keeps only evidence that cannot be recovered from another field (refund template raw bytes, role public keys, fee rate, signatures, funding transaction). It is an application-side structure, not a wire Kind. Implementations derive RefundTemplateTxID, FundingTxID, the fixed output index, pool amount, and pool locking script whenever the proof is consumed; those derived values may be used as database indexes but MUST NOT be serialized back into OpeningProof.

### Kind 12 · PoolCloseRequest (Buyer → Seller)

Closing uses the same pool correlation ID and opening evidence defined above. Kind 12 is the fixed five-element deterministic-CBOR buyer request:

```text
[1, 12,
  refund_template_txid,
  unsigned_close_transaction_raw,
  buyer_close_transaction_signature]
```

`refund_template_txid` is the non-zero 32-byte pool correlation ID derived from the buyer's OpeningProof and MUST be the first business field. `unsigned_close_transaction_raw` is the exact final-close candidate built from the buyer's selected payment state. `buyer_close_transaction_signature` is the buyer's detached MultisigPool transaction signature over that candidate, not a `SignWireDocument` signature. The seller MUST compare the ID with its own OpeningProof, validate the candidate against that opening, and verify the buyer transaction signature before signing.

### Kind 13 · PoolCloseResponse (Seller → Buyer)

Kind 13 is the fixed four-element deterministic-CBOR seller response:

```text
[1, 13,
  refund_template_txid,
  complete_close_transaction_raw]
```

The response repeats `refund_template_txid` as its first business field. `complete_close_transaction_raw` is the exact final-close transaction with both parties' transaction signatures in its unlocking script. The buyer MUST compare the ID with its own OpeningProof and fully verify the transaction before submission.

Both close Kinds use strict deterministic decoding and reject missing, extra, malformed, or non-canonical fields. Each close transaction is limited to 65,536 bytes and must have exactly one input and three outputs. The Go and TypeScript SDK transaction parsers also impose an implementation resource limit of 10,000 inputs and 10,000 outputs on any transaction, including funding transactions; this is not a Bitcoin consensus rule. The Artifact defines the message shape and pool routing only; storage, retries, transaction broadcast, and confirmation tracking remain application responsibilities. The correlation ID is never the on-chain transaction ID of the close transaction.
