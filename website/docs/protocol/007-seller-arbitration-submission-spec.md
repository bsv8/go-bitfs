---
id: 007-seller-arbitration-submission-spec
title: 007 · v3 Seller arbitration submission specification
---

# 007 · v3 Seller arbitration submission specification

007 defines how a seller requests an Arbiter detached signature under final buyer payment authorization. The current protocol major is 3, the payment pool is bound to `bitfs.pool.v4`, and `ArbiterAmount = 0`.

## Evidence package

```text
ArbitrationRequest = [
  3,
  pool_opening_proof_cbor,
  payment_authorization_cbor,
  unsigned_state_tx_raw,
  seller_transaction_signature
]

ArbitrationResponse = [
  3,
  payment_authorization_hash,
  unsigned_state_tx_hash,
  arbiter_transaction_signature
]
```

The candidate MUST be a three-output `[Buyer, Seller, Arbiter]` state with an empty input unlocking script and a present Arbiter output of amount 0. Seller and Arbiter signatures MUST cover the same unsigned transaction. The arbiter does not construct a replacement, modify the candidate, or query an external database for missing evidence.

After receiving the response, the seller rechecks both hashes and the arbiter signature and creates the final transaction only through `MergeArbitratedPoolSellerArbiterSignatures`. 007 does not require the buyer to sign 005 for this dispute, and go-bitfs does not permit a Buyer+Arbiter business path.
