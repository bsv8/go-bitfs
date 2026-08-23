---
id: 007-seller-arbitration-submission-spec
title: 007 · v4 Seller arbitration submission specification
---

# 007 · v4 Seller arbitration submission specification

007 is a destructive v4 hard switch. The old six-element request and old
five-element response are invalid. The Arbiter receives Seller-signed source
context, Buyer-signed terms, and the exact payload bundle; it independently
rebuilds the payment transaction and signs only after the application has
persisted the custody evidence.

## Wire documents

```text
ArbitrationRequest = [
  4, 8, arbitration_claim_cbor, seller_claim_signature,
  content_payloads_cbor
]

ArbitrationClaim = [
  pool_output_satoshis, pool_output_locking_script, refund_template_raw,
  terms_cbor, buyer_signature
]

ArbitrationResponse = [
  4, 9, arbitration_result_cbor, arbiter_result_signature,
  arbiter_transaction_signature
]

ArbitrationResult = [request_commitment, content_payloads_hash,
                     unsigned_state_tx_hash]
```

`Claim` and `Result` contain no version or kind. The transport Kind and the
body's second element must agree. All child documents are deterministic CBOR
embedded as `bstr`; decoders reject non-canonical bytes, wrong array lengths,
tags, indefinite lengths, and trailing bytes.

The Seller message signature is:

```text
seller_claim_signing_cbor = [4, 8, exact_claim_cbor]
seller_claim_signature = SignMessage(SellerKey, seller_claim_signing_cbor)
```

The Result message signature is:

```text
arbiter_result_signing_cbor = [4, 9, exact_result_cbor]
arbiter_result_signature = SignMessage(ArbiterKey, arbiter_result_signing_cbor)
```

`request_commitment` is `SHA-256(seller_claim_signing_cbor)`;
`content_payloads_hash` is `SHA-256(exact content_payloads_cbor)`; and
`unsigned_state_tx_hash` is `SHA-256(exact unsigned candidate transaction)`. A
transaction signature is the independent `ForkID|All` signature and cannot
replace the Result message signature.

## Claim and custody validation

The pool locking script must be the exact compressed-key script in fixed
`[Buyer, Seller, Arbiter]` order:

```text
OP_2 PUSHDATA(33-byte Buyer) PUSHDATA(33-byte Seller)
PUSHDATA(33-byte Arbiter) OP_3 OP_CHECKMULTISIG
```

The Arbiter verifies the Buyer signature over the exact `terms_cbor`, derives
`RefundTemplateTxID = TxID(refund_template_raw)`, and compares it with the
Buyer-signed terms. It does not receive `OpeningProof`, `FundingTx`, fee rate,
previous state, candidate raw bytes, or a Seller transaction signature.

The exact payload child document must contain 1–64 non-empty payloads. Each
payload is canonical, within the MasterSeed block-size limit, in the exact
003 order, and has the corresponding SHA-256. One bad item rejects the whole
batch. Payloads are not copied into the Seller message signature; they are
bound through the Buyer-signed content hashes and committed by the Result.

This source context is an offline Seller claim. The SDK does not prove that
the claimed amount/script belongs to an on-chain FundingTx output, is
confirmed, or remains unspent. A wrong source context makes the eventual
ForkID signature unusable and is the Seller's reconciliation risk.

## Independent candidate construction

`pool.BuildArbitrationPaymentFromClaim` accepts only the source amount, source
locking script, refund template raw bytes, target sequence, and absolute Seller
amount. It validates the refund shape and role output scripts, derives the
retained refund fee, and constructs:

```text
Input:  refund outpoint, target sequence, empty unlocking script
        source amount/script in memory for sighash only
Outputs: Buyer = pool - refund_fee - SellerAmountAfterSat
         Seller = SellerAmountAfterSat
         Arbiter = 0
LockTime: refund template locktime
```

The Seller and Arbiter call this same core and require byte equality. The
Arbiter flow is two phase:

```text
PreparePayment
  -> application atomically persists exact Kind 8 and payload bundle
  -> SignPreparedPayment
  -> persist/send exact Kind 9
```

The SDK has no database, object store, HTTP client, broadcaster, or UTXO
lookup. Applications must retain exact request/result bytes for idempotency,
replay, custody retention, and Buyer recovery.

After receiving Kind 9, the Seller verifies all three Result hashes, the
Arbiter Result signature, and the Arbiter transaction signature against its
own rebuilt candidate. Only then does it create its transaction signature and
call `MergeArbitratedPoolSellerArbiterSignatures`.
