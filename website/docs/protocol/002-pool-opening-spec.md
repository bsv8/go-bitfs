---
id: 002-pool-opening-spec
title: "002 · Fee Pool Opening Specification"
---

# 002 · Fee Pool Opening Specification

The Buyer creates a pool lock using `ArbitratedPoolRoles{Buyer, Seller, Arbiter}` from MultisigPool v4. The public key order is fixed as `[Buyer, Seller, Arbiter]`.

The opening/refund state MUST contain exactly three funding outputs: Buyer, Seller, and Arbiter. The Seller and Arbiter initial amounts are 0; the Arbiter output MUST still be present. The opening sequence is returned by the MultisigPool dependency and is currently 2; go-bitfs MUST NOT rewrite the sequence, locktime, fee, or script.

The Buyer produces a detached Buyer signature over the unsigned RefundTx, and the Seller produces a detached Seller signature over the same unsigned transaction. Both parties MUST persist the complete OpeningProof before delivering or broadcasting the FundingTx. Time-based refunds MUST be merged exclusively via `MergeArbitratedPoolBuyerSellerSignatures`.

The pool output in FundingTx MUST be output index 0. RefundTx carries that outpoint directly. RefundTemplateTxID is the canonical transaction ID of the unsigned RefundTx and is the unified pool correlation ID; FundingTxID is read from its input. The pool amount is derived from RefundTx's Buyer output plus the canonical MultisigPool fee, and the pool locking script is derived from the ordered participant keys. These values MUST NOT be duplicated in either the presign request or OpeningProof.

Kind 2 RefundPresignRequest is a fixed seven-element wire array `[1, 2, refund_template_raw, buyer_public_key, seller_public_key, arbiter_public_key, miner_fee_rate_satoshis_per_kilobyte, buyer_refund_transaction_signature]` under `protocol.WireVersion = 1`. The wire version uniquely selects the MultisigPool transaction rules, so separate discriminators are forbidden.

The locally persisted OpeningProof keeps only evidence that cannot be recovered from another field (refund template raw bytes, role public keys, fee rate, signatures, funding transaction). It is an application-side structure, not a wire Kind. Implementations derive RefundTemplateTxID, FundingTxID, the fixed output index, pool amount, and pool locking script whenever the proof is consumed; those derived values may be used as database indexes but MUST NOT be serialized back into OpeningProof.
