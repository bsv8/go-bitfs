---
id: 002-pool-opening-spec
title: "002 · v3 Fee Pool Opening Specification"
---

# 002 · v3 Fee Pool Opening Specification

The Buyer creates a pool lock using `ArbitratedPoolRoles{Buyer, Seller, Arbiter}` from MultisigPool v4. The public key order is fixed as `[Buyer, Seller, Arbiter]`.

The opening/refund state MUST contain exactly three funding outputs: Buyer, Seller, and Arbiter. The Seller and Arbiter initial amounts are 0; the Arbiter output MUST still be present. The opening sequence is returned by v4 and is currently 2; go-bitfs MUST NOT rewrite the sequence, locktime, fee, or script.

The Buyer produces a detached Buyer signature over the unsigned RefundTx, and the Seller produces a detached Seller signature over the same unsigned transaction. Both parties MUST persist the complete OpeningProof before delivering or broadcasting the FundingTx. Time-based refunds MUST be merged exclusively via `MergeArbitratedPoolBuyerSellerSignatures`.

The OpeningProof deterministic CBOR is `[3, "bitfs.pool.v4", 4, refund_tx, spend_txid, funding_txid, output_index, pool_amount, pool_lock, buyer_pubkey, seller_pubkey, arbiter_pubkey, fee_rate, buyer_signature, seller_signature, funding_tx]`.
