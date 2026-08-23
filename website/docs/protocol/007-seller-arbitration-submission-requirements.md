---
id: 007-seller-arbitration-submission-requirements
title: 007 · Seller arbitration submission requirements
---

# 007 · Seller arbitration submission requirements

007 is the v4 custody-and-settlement exception for a Buyer-signed 003 whose
normal 004/005 path cannot complete. The Seller submits the exact content
payloads and signs a Claim. The Arbiter verifies and holds those bytes, builds
the payment independently, and signs only after the application confirms
persistence.

## Required evidence

The Seller MUST send exactly the new five-element Kind 8 request. Its Claim
contains only:

- the claimed pool output satoshis and exact role-ordered P2MS locking script;
- the canonical unsigned RefundTx raw bytes;
- the exact Buyer-signed 003 `TermsCBOR` and Buyer signature.

The outer request separately carries the Seller message signature over
`[4, 8, exact_claim_cbor]` and the canonical 1–64 item
`content_payloads_cbor`.
It MUST NOT contain OpeningProof, FundingTx, fee rate, previous state,
candidate raw bytes, `RefundTemplateTxID` as a duplicate field, or a Seller
transaction signature.

The Claim locking script fixes the role order `[Buyer, Seller, Arbiter]`.
The SDK validates the Buyer signature, RefundTx ID against the terms, output
shape, source arithmetic, payload count/order/size/hash, and all canonical
CBOR. It does not claim to validate on-chain UTXO existence, confirmation, or
unspent status; a wrong Seller source context is recorded by the application
as an unspendable-source reconciliation failure.

## Arbiter boundary

The application MUST persist the exact inbound request and payload bundle
before requesting a transaction signature:

```text
raw Kind 8 received
  -> PreparePayment
  -> atomic custody persistence
  -> SignPreparedPayment
  -> persist/send exact Kind 9
```

`PreparePayment` has no transaction-signing side effect. It returns opaque
prepared evidence with deep-copy getters for the request commitment, payload
hash, terms hash, payloads, deadline, and unsigned candidate. On restart, the
application re-runs `PreparePayment` from the saved exact Kind 8 bytes; it
must not fabricate the opaque prepared value.

The Arbiter Result commits to the Seller Claim signing-domain hash, exact
payload child-document hash, and exact unsigned candidate hash. The Arbiter
Result signature and the `ForkID|All` transaction signature are separate
credentials; neither can substitute for the other.

## Seller completion

The Seller MUST rebuild the same candidate from the Claim primitives after
receiving Kind 9. It verifies the Claim, Buyer terms signature, all Result
hashes, Result message signature, and Arbiter transaction signature before
creating its own transaction signature. It then merges only through
`MergeArbitratedPoolSellerArbiterSignatures`. Broadcasting, reconciliation,
Buyer retrieval authorization, retention, and idempotency are application
responsibilities.
