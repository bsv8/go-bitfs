---
id: 005-cumulative-payment-spec
title: "005 · v4 Cumulative Payment Specification"
---

# 005 · v4 Cumulative Payment Specification

005 is the normal fulfillment message of the 003 Final Payment Authorization. The transaction template, fees, sequence number, outputs, and signatures are uniquely determined by MultisigPool v4.0.0; go-bitfs only passes the authorization hash, the unsigned state transaction, and the independent Buyer signature.

All state transactions have exactly three funding outputs fixed as `[Buyer, Seller, Arbiter]`: output[0] is Buyer, output[1] is Seller with an absolute cumulative amount, and output[2] is Arbiter with a fixed amount of 0. The Buyer amount and fees are calculated by MultisigPool v4 and MUST NOT be copied or patched by the business layer.

## 005 CBOR

```text
CumulativePaymentUpdateCBOR = deterministic CBOR([
  4,
  refund_template_txid,
  payment_authorization_hash,
  unsigned_state_tx_raw,
  buyer_transaction_signature
])
```

The unsigned transaction MUST have exactly one input and three funding outputs; the input `unlockingScript` MUST be empty and MUST NOT carry a single signature or the final dual-signed transaction. After verifying the Buyer's independent signature and the v4-compliant state, the Seller produces an independent Seller signature on the same unsigned transaction; the complete transaction is finally generated only via `MergeArbitratedPoolBuyerSellerSignatures`.

When submission fails, times out, or the txid/sequence number is inconsistent, the calling application MUST NOT advance its own accepted-payment record until its chosen node policy confirms the submitted transaction. If the result is ambiguous, the application may record an application-local uncertain state and reconcile it by txid or outpoint. The protocol SDK defines no uncertain state, persistence hook, node interface, or reconciliation workflow; broadcasting and recording outcomes are application responsibilities.

The 007 arbitration path does not depend on the Buyer signature from this 005 message. The arbitration path uses the same three-output rule, with signatures merged by Seller and Arbiter via `MergeArbitratedPoolSellerArbiterSignatures`.
