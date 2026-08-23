---
id: 007-seller-arbitration-submission-spec
title: 007 · v4 Seller arbitration submission specification
---

# 007 · v4 Seller arbitration submission specification

007 is a destructive v4 hard switch. The old five-element Kind 9 result
response is invalid. Kind 9 is now a four-element receipt response that pays
the Arbiter a positive, explicitly decided fee, and the receipt binds the
Claim ID, that fee, and the arbitration transaction signature together under
one ordinary message signature. The Arbiter receives Seller-signed source
context, Buyer-signed terms, and the exact payload bundle; it independently
rebuilds the paid payment transaction and signs only after the application has
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
  4, 9, arbitration_receipt_cbor, arbiter_receipt_signature
]

ArbitrationReceipt = [arbitration_claim_id, arbiter_amount_sat,
                      arbiter_transaction_signature]
```

`Claim` and `Receipt` contain no version or kind. The transport Kind and the
body's second element must agree. All child documents are deterministic CBOR
embedded as `bstr`; decoders reject non-canonical bytes, wrong array lengths,
tags, indefinite lengths, and trailing bytes. Legacy five-element Kind 9 bytes
fail deterministically; there is no dual-shape decoder.

The Seller message signature is:

```text
seller_claim_signing_cbor = [4, 8, exact_claim_cbor]
seller_claim_signature = SignMessage(SellerKey, seller_claim_signing_cbor)
```

The Receipt message signature is:

```text
arbiter_receipt_signing_cbor = [4, 9, exact_receipt_cbor]
arbiter_receipt_signature = SignMessage(ArbiterKey, arbiter_receipt_signing_cbor)
```

The Claim ID is `arbitration_claim_id = SHA-256(seller_claim_signing_cbor)`,
fixed at 32 bytes. It indirectly binds the exact Claim CBOR, the exact Buyer
terms, and the ordered content hashes. A successful receipt requires
`arbiter_amount_sat > 0`; zero never means free, declined, or undecided. The
transaction signature is the independent `ForkID|All` signature and cannot
replace the Receipt message signature; neither signature can be substituted
into the other's verification path.

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
bound through the Buyer-signed content hashes and through the Claim ID.

This source context is an offline Seller claim. The SDK does not prove that
the claimed amount/script belongs to an on-chain FundingTx output, is
confirmed, or remains unspent. A wrong source context makes the eventual
ForkID signature unusable and is the Seller's reconciliation risk.

## Independent candidate construction

`pool.BuildArbitrationPaymentFromClaim` accepts only the source amount, source
locking script, refund template raw bytes, target sequence, absolute Seller
amount, and the explicit positive arbitration fee. It validates the refund
shape and role output scripts (the refund template itself still requires zero
Seller/Arbiter initial amounts), derives the retained refund fee, and
constructs exactly three funded outputs:

```text
Input:  refund outpoint, target sequence, empty unlocking script
        source amount/script in memory for sighash only
Outputs: Buyer   = spendable - SellerAmountAfterSat - ArbiterAmountSat
         Seller  = SellerAmountAfterSat
         Arbiter = ArbiterAmountSat (> 0)
         where spendable = pool - refund_fee
LockTime: refund template locktime
```

Buyer + Seller + Arbiter + refund fee always equals the pool output exactly,
with overflow-free compare-then-subtract arithmetic. A Seller amount already
above `spendable`, or a fee above the remaining balance, fails with
`pool.ErrInsufficientBalance`; a zero fee is rejected as invalid evidence.
Exhausting the Buyer remainder to exactly zero is a legal boundary as long as
all three outputs exist.

The Seller and Arbiter call this same core and require byte equality. The
Arbiter flow is two phase:

```text
application computes arbiter_amount_sat from its own fee policy
PreparePayment(request, blockHeight, arbiterAmountSat)
  -> application atomically persists exact Kind 8, Claim ID, fee, and payload bundle
  -> SignPreparedPayment
  -> persist/send exact Kind 9
```

The SDK has no database, object store, HTTP client, broadcaster, UTXO lookup,
or fee policy. Applications must retain exact request/response bytes for
idempotency plus custody retention and Buyer recovery. Replay is gated on
exact bytes, not the Claim ID alone: only an identical Claim ID with
identical exact Kind 8 bytes replays the saved response bytes without
re-pricing or re-signing; a same-ID/different-exact-Claim input is a
hash-collision alarm; a same-Claim/different-outer-signature-or-payload input
is first fully re-validated with the frozen fee (invalid variants are rejected
as evidence errors, fully valid variants are duplicate-evidence conflicts);
a different Claim ID gets its own record.

After receiving Kind 9, the Seller recomputes the Claim ID from its own Claim
bytes, recovers the Arbiter public key from the role-ordered pool script,
verifies the Receipt message signature over `[4, 9, exact_receipt_cbor]`,
rebuilds the candidate with the receipt's arbiter amount, and verifies the
Arbiter transaction signature against it. Only then does it create its own
transaction signature and call `MergeArbitratedPoolSellerArbiterSignatures`.
The completed state carries `ArbiterAmountSat` equal to the receipt amount and
a Seller amount equal to the Buyer-authorized absolute amount.

## Retrieval boundary

007 itself ends when the exact canonical Kind 9 is persisted. How a buyer
retrieves custodied content is fixed separately by step 008 (Kind 10/11):
the SDK owns the wire shapes and signature domains there, while applications
own persistence, nonce deduplication, TLS transport, and retention.
