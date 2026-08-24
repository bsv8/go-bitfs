---
id: 005-cumulative-payment-spec
title: "005 · Cumulative Payment Specification"
---

# 005 · Cumulative Payment Specification

005 is the normal fulfillment message of the 003 Final Payment Authorization. It is a **minimal payment credential**: the `payment_authorization_id` plus the Buyer transaction signature. The pool correlation ID (`RefundTemplateTxID`) and the unsigned state transaction are **never transmitted**; both the Buyer and the Seller deterministically rebuild the exact same unsigned state transaction locally from the OpeningProof, the previous PaymentState, and the signed 003 referenced by the ID, through the single `BuildPaymentUpdate` implementation of MultisigPool v4.0.0.

The payment authorization ID is a content-addressed lookup key, not a reversible encoding: it MUST NOT be treated as a pool ID, decoded into amounts or sequences, or guessed from a connection. The receiving application must look up the exact original signed 003 saved under that ID before any validation can run.

## Wire shape (Kind 7)

```text
kind-7-payment-update = [
    1,                                    ; wire-version, injected by the encoder
    7,                                    ; wire kind
    payment_authorization_id,             ; bstr .size 32 = SHA-256(exact payment_authorization_cbor)
    buyer_payment_transaction_signature   ; sighash signature over the locally rebuilt state transaction
]
```

Legacy containers — including the pre-v1 five-element container that carried the refund template txid, the authorization hash, and the raw candidate on the wire — are rejected outright; no length-based legacy decoder exists inside `protocol.WireVersion = 1`. Decoders also reject missing fields, extra fields, wrong versions, indefinite lengths, tags, non-canonical encodings, non-shortest length headers, and trailing bytes with stable invalid-evidence errors.

## Hard-Switch Gate

This four-element Kind 7 shape replaced all pre-switch containers in one atomic launch-time switch with no dual decoder and no migration adapter. Before deploying, every participant must confirm that no independent external client, persistent queue, or production node still carries pre-switch 005 bytes; if any exist, the hard switch MUST stop and a new major/transport family with an explicit migration strategy MUST be defined instead. Two mutually incompatible shapes must never both claim interoperability under one version.

`payment_authorization_id` is exactly 32 bytes and equals SHA-256 of the exact signed 003 payment authorization document. `buyer_payment_transaction_signature` is a low-S DER ECDSA signature over the MultisigPool v4 sighash (SHA-256d preimage, ForkID|All) of the locally rebuilt unsigned state transaction — never over the authorization ID itself, the payment authorization CBOR, the Kind 7 CBOR, a txid, or any text form.

## Rebuilt State Transaction

All state transactions have exactly three funding outputs fixed as `[Buyer, Seller, Arbiter]`: output[0] is Buyer, output[1] is Seller with an absolute cumulative amount, and output[2] is Arbiter with a fixed amount of 0. The input outpoint, Buyer amount, Arbiter zero amount, fees, sequence, and locktime are uniquely determined by:

```text
OpeningProof
+ previous PaymentState
+ payment_authorization_cbor.PaymentSequence
+ payment_authorization_cbor.SellerAmountAfterSatoshis
+ fixed MultisigPool v4 construction rules
= exact unsigned payment state transaction
```

The rebuilt transaction MUST have exactly one input and three funding outputs; the input `unlockingScript` MUST be empty. After verifying the Buyer's signature over the rebuilt transaction and the protocol-compliant state, the Seller produces an independent Seller signature on the same rebuilt transaction; the complete transaction is finally generated only via the single Buyer+Seller merge entry (`MergeArbitratedPoolBuyerSellerSignatures`). If the Buyer's reconstructed bytes and the Seller's reconstructed bytes ever differ, that is a hard failure to record and fix — never a reason to fall back to wire-supplied raw transactions.

## Application Routing and Boundaries

The application owns a unique index `payment_authorization_id -> {exact_signed_003, content_delivery_state, refund_template_txid, processing_status}`. Upon receiving Kind 7 the Seller application must: strictly decode the four-element 005; load the exact original 003 by ID; cross-compare every binding; serialize per-pool acceptance in its own transaction/CAS; and pass all explicit evidence into the stateless SDK. The SDK queries no database, scans no pools, and holds no locks.

When submission fails, times out, or the txid/sequence number is inconsistent, the calling application must first persist the complete raw/txid/sequence/auth-ID candidate and reconcile it by txid or outpoint under its chosen node policy before advancing its accepted-payment record. The protocol SDK defines no uncertain state, persistence hook, node interface, or reconciliation workflow; broadcasting and recording outcomes are application responsibilities.

The 007 arbitration path does not depend on this minimal 005. It carries a
Seller-signed Claim with source amount/script, RefundTx, Buyer-signed 003
authorization, and the exact 004 payload bundle. It deliberately omits OpeningProof,
FundingTx, previous state, candidate raw, and Seller transaction signature;
the Arbiter independently calls the same deterministic candidate builder and
signs only after application custody persistence. The Seller rebuilds the
candidate and merges through `MergeArbitratedPoolSellerArbiterSignatures`.
