---
id: 002-pool-opening-spec
title: "002 · v4 Fee Pool Opening Specification"
---

# 002 · v4 Fee Pool Opening Specification

The Buyer creates a pool lock using `ArbitratedPoolRoles{Buyer, Seller, Arbiter}` from MultisigPool v4. The public key order is fixed as `[Buyer, Seller, Arbiter]`.

The opening/refund state MUST contain exactly three funding outputs: Buyer, Seller, and Arbiter. The Seller and Arbiter initial amounts are 0; the Arbiter output MUST still be present. The opening sequence is returned by v4 and is currently 2; go-bitfs MUST NOT rewrite the sequence, locktime, fee, or script.

The Buyer produces a detached Buyer signature over the unsigned RefundTx, and the Seller produces a detached Seller signature over the same unsigned transaction. Both parties MUST persist the complete OpeningProof before delivering or broadcasting the FundingTx. Time-based refunds MUST be merged exclusively via `MergeArbitratedPoolBuyerSellerSignatures`.

The pool output in FundingTx MUST be output index 0. RefundTx carries that outpoint directly. SpendTxID is the canonical transaction ID of RefundTx; FundingTxID is read from its input. The pool amount is derived from RefundTx's Buyer output plus the canonical MultisigPool fee, and the pool locking script is derived from the ordered participant keys. These values MUST NOT be duplicated in either the presign request or OpeningProof.

The RefundPresignRequest deterministic CBOR is `[4, refund_tx, buyer_pubkey, seller_pubkey, arbiter_pubkey, fee_rate, buyer_signature]`. Workflow version 4 uniquely selects the MultisigPool protocol and version, so separate discriminators are forbidden.

The transmitted and locally persisted OpeningProof deterministic CBOR is `[4, refund_tx, buyer_pubkey, seller_pubkey, arbiter_pubkey, fee_rate, buyer_signature, seller_signature, funding_tx]`. It contains only evidence that cannot be recovered from another field. Implementations derive SpendTxID, FundingTxID, the fixed output index, pool amount, and pool locking script whenever the proof is consumed; those derived values may be used as database indexes but MUST NOT be serialized back into OpeningProof.
