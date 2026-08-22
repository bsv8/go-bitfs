---
id: 007-seller-arbitration-submission-spec
title: 007 · v4 Seller arbitration submission specification
---

# 007 · v4 Seller arbitration submission specification

007 defines how a seller requests an Arbiter detached signature under final buyer payment authorization. The current protocol major is 4, and `ArbiterAmount = 0`.

## Evidence package

```text
ArbitrationRequest = [
  4,
  refund_template_txid,
  pool_opening_proof_cbor,
  payment_authorization_cbor,
  unsigned_state_tx_raw,
  seller_transaction_signature
]

ArbitrationResponse = [
  4,
  refund_template_txid,
  payment_authorization_hash,
  unsigned_state_tx_hash,
  arbiter_transaction_signature
]
```

`pool_opening_proof_cbor` is the nine-field v4 OpeningProof defined by 002. It carries raw RefundTx/FundingTx, participant keys, fee rate, and both refund signatures; it does not carry derived transaction IDs, the fixed output index, pool amount, locking script, or redundant MultisigPool discriminators.

The candidate MUST be a three-output `[Buyer, Seller, Arbiter]` state with an empty input unlocking script and a present Arbiter output of amount 0. Seller and Arbiter signatures MUST cover the same unsigned transaction. The arbiter does not construct a replacement, modify the candidate, or query an external database for missing evidence.

`refund_template_txid` is the pool correlation ID derived from the unsigned RefundTx. The arbiter MUST compare it with the hash derived from `pool_opening_proof_cbor`; the seller MUST additionally bind the response's `refund_template_txid` to the original request before merging.

After receiving the response, the seller rechecks both hashes and the arbiter signature and creates the final transaction only through `MergeArbitratedPoolSellerArbiterSignatures`. 007 does not require the buyer to sign 005 for this dispute, and go-bitfs does not permit a Buyer+Arbiter business path.
