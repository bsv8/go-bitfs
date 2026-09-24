---
id: external-hooks-and-data-types
title: 02 · External hooks and data types
---

# 02 · External hooks and data types

The SDK is a stateless protocol library: it owns message encoding, signature
verification, pricing, transaction construction, and protocol validation, while
the calling application owns persistence, concurrency, content storage,
transport, node broadcasting, and the observation of time and block heights.
There is no Verifier callback, no Store, no node hook, and no clock hook; every
external fact crosses the boundary either as an explicit method input, as a
`protocol.Facts{Now, BlockHeight}` value, or through the single signer port.

## Signing and key custody: one port

The only key-custody capability in the SDK is the constrained `protocol.Signer`
port:

```go
// package protocol
type Signer interface {
    // PublicKey 返回本 Signer 固定的压缩公钥；每次纯函数调用都会绑定并验证它，
    // 调用生命周期内不得变化。
    PublicKey() PublicKey
    // Sign 对 SDK 已构造好的 32 字节 digest 做 secp256k1 签名，返回不带
    // 交易 sighash flag 的 low-S DER。Signer 绝不能自行哈希。
    Sign(ctx context.Context, request SigningRequest) ([]byte, error)
}

// SigningRequest 携带 Purpose（wire_message / transaction）、WireKind 与 Digest；
// 只供 HSM/KMS 策略审计，不替代任何既定签名预映像。
```

The signer is a **capability port, not a replaceable protocol policy**. It can
never supply a custom hash function, preimage, sighash flag, verifier, CBOR
encoder, price rule, or role decision; all verification stays fixed inside the
SDK. Local software keys enter through the only provided adapter:

```go
signer, err := protocol.NewPrivateKeySigner(privateKey) // privateKey 为 *ec.PrivateKey
outbound, terms, err := seller.CreateQuote(ctx, facts, signer, draft)
kind2, evidence, err := buyer.PrepareOpening(ctx, input, signer)
```

Each pure-function entry receives the signer per call; the SDK binds and
validates the compressed public key derived from that signer for the duration of
the call only, and re-checks that supplied opening evidence belongs to the
signer's role before signing anything. No cross-step object retains the signer.

The SDK never accepts a seed, key-export callback, or signature-verifier
callback either. Every ordinary message signature follows one fixed path inside
the SDK: the digest over the typed signing input is constructed once, handed to
the Signer, normalized to low-S DER, and re-verified against the fixed role key
before returning. Callers must not hash a second time before signing.
Transaction signatures always use the fixed MultisigPool sighash (`ForkID|All`)
and are never hashed a second time.

Public keys in a quote, opening proof, content request, or payment state are
protocol evidence. Callers cannot replace participant verification or
reconfigure the buyer/seller/arbiter roles: verification is fixed and not
substitutable.

## Persistence belongs to the application

There is no Store interface and no checkpoint class in the SDK. Every step
returns plain evidence packages — for example `buyer.BuyerOpeningEvidence`,
`buyer.BuyerPoolEvidence`, `buyer.BuyerAuthorizationEvidence`,
`seller.SellerOpeningEvidence`, `seller.SellerDeliveryEvidence`, and
`arbiter.PreparedArbitrationEvidence` — that contain raw bytes and explicit
fields only, and require them again as explicit arguments in later steps.
Applications persist those evidence bytes in their own database keyed by
`RefundTemplateTxID` (or by authorization ID), serialize concurrent work per
pool, and implement retries, outboxes, and crash recovery themselves. Every step
re-verifies the complete evidence from raw bytes before acting, so restore is
just passing the persisted data back in; the SDK adds no locks, leases, mutexes,
or process-serialization of any kind.

## Content bytes are caller-supplied

The seller reads seed/block payload bytes from its own storage and passes them
as an ordered batch via `seller.DeliveryInput.ContentPayloads`; the buyer passes
ordered content hashes via `buyer.RequestContentInput.ContentHashes` and
verified seeds via `Seed`. The pure steps derive every content kind from
evidence (a hash equal to the quote SeedHash is the seed, everything else must
be committed by that seed), verify hashes, seed structure, block membership,
expected lengths, quote terms, and request/delivery signatures against those
explicit bytes, and accept or reject the whole batch atomically. Verification
returns the verified payload batch as data (the first result of
`buyer.VerifyDelivery`, in authorized order); saving it to final storage is the
application's job.

## Time and height facts are explicit inputs

The SDK has no clock injection and no node access, and it reads no system time.
Every time-sensitive call receives one explicit `protocol.Facts{Now, BlockHeight}`
value; operations that need only a time reject a zero `Now`, and operations that
need a height reject a zero `BlockHeight`. The SDK never queries a node for the
current height, never falls back to the system clock, and never fabricates a
value. A height-source outage must delay or reroute refund operations, never
fabricate a value.

## Protocol input and result types

The pure steps accept raw wire bytes plus plain input structs and return raw
wire bytes plus plain evidence packages to persist first:

- `buyer.PrepareOpeningInput` carries raw funding bytes, expiry locktime, fee
  rate, and seller/arbiter public keys; the step returns the outbound exact
  Kind 2 Artifact plus `buyer.BuyerOpeningEvidence` — persist the evidence
  before sending.
- `buyer.RequestContentInput` carries the exact Kind 1 quote bytes, pool
  evidence, ordered content hashes, delivery deadline, and seed; the step
  returns the outbound Kind 5 Artifact plus `buyer.BuyerAuthorizationEvidence`
  holding the exact signed Kind 5.
- `buyer.VerifyDeliveryInput` verifies the exact Kind 6 delivery against the
  persisted authorization evidence; the step returns the verified payloads and
  the single outbound Kind 7 credential.
- `seller.DeliveryInput` / `seller.SellerDeliveryEvidence` on the seller side
  return the outbound Kind 6 Artifact plus the exact Kind 1/Kind 5/Kind 6 bytes
  needed later by `seller.CompletePayment` and `seller.PrepareArbitration`.
- `pool.UnsignedPayment` and `pool.SignedPayment` distinguish locally rebuilt
  unsigned states, detached signatures, and complete transactions. Steps return
  complete transaction bytes for the application to broadcast; nothing is ever
  named "submitted" or "accepted" inside the SDK.

The correlation field across these types is `pool.RefundTemplateTxID` — a
dedicated `[32]byte` type carrying the canonical TxID of the refund template
transaction without embedded role signatures (CDDL label
`refund-template-txid`). It is not a SHA-256 of raw bytes, not a byte-reversed
hash, and not the txid of the final broadcast refund transaction.

The wire package maps domain values to canonical Kind 1–13 CBOR as immutable
Artifacts whose `Bytes()` are transmitted and stored unchanged. The optional
`transport` package binds those exact bytes to the shared
`/bitfs/wire/1.0.0` bitcoin-libp2p stream profile with unsigned-varint length
framing. Host lifecycle, routing, retries, HTTP, queues, databases, and browser
session policy remain application-owned; no transport may re-encode an
Artifact or add a hidden pool/session identity.

## What is not an extension point

There is no verifier strategy, workflow clock, store/repository hook,
transaction engine hook, lease or locker, content source/sink, backend port,
private-key provider, or application-supplied transaction-ID calculator. Those
abstractions would allow a caller to replace business rules that define the
protocol, or would smuggle infrastructure side effects back into the SDK. Only
key custody crosses this boundary, per call, through the constrained
`protocol.Signer` port; everything else flows through explicit inputs, explicit
facts, and returned raw bytes/evidence.
