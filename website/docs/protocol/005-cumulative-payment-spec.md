---
id: 005-cumulative-payment-spec
title: "005 · v4 Cumulative Payment Specification"
---

# 005 · v4 Cumulative Payment Specification

005 is the normal fulfillment message of the 003 Final Payment Authorization. It is a **minimal payment credential**: the payment authorization hash plus the Buyer transaction signature. The pool correlation ID (`RefundTemplateTxID`) and the unsigned state transaction are **never transmitted**; both the Buyer and the Seller deterministically rebuild the exact same unsigned state transaction locally from the OpeningProof, the previous PaymentState, and the signed 003 referenced by the hash, through the single `BuildPaymentUpdate` implementation of MultisigPool v4.0.0.

The authorization hash is a content-addressed lookup key, not a reversible encoding: it MUST NOT be treated as a pool ID, decoded into amounts or sequences, or guessed from a connection. The receiving application must look up the exact original SignedContentRequest saved under that hash before any validation can run.

## 005 CBOR

```text
CumulativePaymentUpdateCBOR = deterministic CBOR([
  4,
  payment_authorization_hash,
  buyer_transaction_signature
])
```

Pre-switch v4 five-element containers (`[4, refund_template_txid, payment_authorization_hash, unsigned_state_tx_raw, buyer_transaction_signature]`) are rejected outright; no length-based legacy decoder exists. Decoders also reject missing fields, extra fields, wrong majors, indefinite lengths, tags, non-canonical encodings, non-shortest length headers, and trailing bytes with stable invalid-evidence errors.

## Hard-Switch Gate

This three-element shape replaced the pre-switch five-element v4 container in one atomic launch-time switch with no dual decoder and no migration adapter. Before deploying, every participant must confirm that no independent external v4 client, persistent queue, or production node still carries pre-switch 005 bytes; if any exist, the same-major hard switch MUST stop and a new major/transport family with an explicit migration strategy MUST be defined instead. Two mutually incompatible shapes must never both claim interoperable v4.

`payment_authorization_hash` is exactly 32 bytes and equals SHA-256 of the signed 003 `TermsCBOR`. `buyer_transaction_signature` is a low-S DER ECDSA signature over the MultisigPool v4 sighash (SHA-256d preimage, ForkID|All) of the locally rebuilt unsigned state transaction — never over the authorization hash itself, the TermsCBOR, the 005 CBOR, a txid, or any text form.

## Rebuilt State Transaction

All state transactions have exactly three funding outputs fixed as `[Buyer, Seller, Arbiter]`: output[0] is Buyer, output[1] is Seller with an absolute cumulative amount, and output[2] is Arbiter with a fixed amount of 0. The input outpoint, Buyer amount, Arbiter zero amount, fees, sequence, and locktime are uniquely determined by:

```text
OpeningProof
+ previous PaymentState
+ 003.PaymentSequence
+ 003.SellerAmountAfterSat
+ fixed MultisigPool v4 construction rules
= exact unsigned payment state transaction
```

The rebuilt transaction MUST have exactly one input and three funding outputs; the input `unlockingScript` MUST be empty. After verifying the Buyer's signature over the rebuilt transaction and the v4-compliant state, the Seller produces an independent Seller signature on the same rebuilt transaction; the complete transaction is finally generated only via the single Buyer+Seller merge entry (`MergeArbitratedPoolBuyerSellerSignatures`). If the Buyer's reconstructed bytes and the Seller's reconstructed bytes ever differ, that is a hard failure to record and fix — never a reason to fall back to wire-supplied raw transactions.

## Application Routing and Boundaries

The application owns a unique index `payment_authorization_hash -> {exact_signed_003, content_delivery_state, refund_template_txid, processing_status}`. Upon receiving Kind 7 the Seller application must: strictly decode the three-element 005; load the exact original 003 by hash; cross-compare every binding; serialize per-pool acceptance in its own transaction/CAS; and pass all explicit evidence into the stateless SDK. The SDK queries no database, scans no pools, and holds no locks.

When submission fails, times out, or the txid/sequence number is inconsistent, the calling application must first persist the complete raw/txid/sequence/auth-hash candidate and reconcile it by txid or outpoint under its chosen node policy before advancing its accepted-payment record. The protocol SDK defines no uncertain state, persistence hook, node interface, or reconciliation workflow; broadcasting and recording outcomes are application responsibilities.

The 007 arbitration path does not depend on this minimal 005 and continues to carry its own self-sufficient evidence package (complete OpeningProof, original 003, unsigned candidate raw, Seller signature), because the Arbiter does not share the Seller's local lookup context. The arbitration path uses the same three-output rule, with signatures merged by Seller and Arbiter via `MergeArbitratedPoolSellerArbiterSignatures`.
