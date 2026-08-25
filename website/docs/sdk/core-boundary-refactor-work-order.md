---
id: core-boundary-refactor-work-order
title: Core boundary refactor work order
---

# Core boundary refactor work order

> **Superseded（已被取代）:** This page's acceptance contract was superseded on
> 2026-08-24 by the hard-switch work order that replaced direct private-key
> workflow construction with the constrained `protocol.Signer` port
> (`protocol.NewPrivateKeySigner`) and made time/height explicit through
> `protocol.Facts`. The earlier decision to forbid a signer port and public
> time facts no longer applies. The infrastructure-side-effect-free boundary
> described below remains in force and unchanged.

This page records the acceptance contract of the completed SDK boundary hard
switch. It supersedes every earlier description in which role workflows could
accept stores, content sources/sinks, or BSV submission backends. Protocol
specifications 001–008 remain authoritative for wire bytes and protocol
behavior; existing wire shapes remain fixed, 007 uses its current five-element
Kind 8 Claim request plus four-element Kind 9 Receipt response shapes and
signing domains, and 008 fixes the four-element Kind 10 buyer retrieval request
plus the Arbiter-signed two-branch Kind 11 response whose available branch
binds the payload bundle through `content_payloads_id`. The
`RefundTemplateTxID` algorithm remains unchanged.

## Product definition

`go-bitfs` is a **stateless, infrastructure-side-effect-free** executable BitFS
protocol specification and role SDK for Buyer, Seller, and Arbiter
implementations. Given explicit protocol inputs, explicit prior state, and one
explicit `protocol.Facts{Now, BlockHeight}` value per call, it strictly decides
whether the inputs are legal and computes the next protocol message,
transaction, signature material, or local role state.

The application owns everything the SDK does not:

- databases, files, transactions, locks, CAS, and unique constraints;
- concurrency serialization per `RefundTemplateTxID` (the SDK has no mutex or lease);
- retries, idempotency, crash recovery, and outboxes;
- peer transport, routing, timeouts;
- node broadcasting, chain queries, and result reconciliation — only the
  application's node adapter may declare that a broadcast was accepted;
- observation of time and block heights, supplied explicitly as Facts values;
  the SDK never reads a clock and never queries a node for height;
- content repositories: bytes are read before a call and passed in; verified
  bytes are returned as data and saved by the application;
- multi-tenant authorization (`RefundTemplateTxID` is a routing ID, not an auth token).

MasterSeed remains the fixed content-proof implementation. MultisigPool v4
remains the fixed BSV pool-transaction implementation. Neither is an
application plugin.

## Required public boundary

Role workflow constructors accept exactly one capability — a constrained
signer fixed at construction:

```go
signer, err := protocol.NewPrivateKeySigner(key) // 本地软件私钥的唯一入口；key 为 *ec.PrivateKey
buyerWf, err := buyer.NewWorkflow(signer)
sellerWf, err := seller.NewWorkflow(signer)
arbiterWf, err := arbiter.NewWorkflow(signer)
```

The signer is a capability port only: it supplies a fixed compressed public key
and signs digests already constructed by the SDK. It can never replace hashing,
preimages, sighash flags, verification, CBOR encoding, pricing, or role rules.
No store, quote store, pending-request store, content sink/source, backend,
node adapter, clock hook, verifier strategy, or locker field exists. Every
method takes its business inputs explicitly (quote, opening proof, previous
payment state, delivery context, content bytes, seed) plus one explicit Facts
value where time or height matters, and returns only computed Artifacts, raw
transactions wrapped in verified values, verified evidence, and opaque local
checkpoints such as `buyer.OpeningCheckpoint`, `buyer.PoolCheckpoint`, and
`seller.DeliveryCheckpoint`. Methods never load, save, send, broadcast, or mark
uncertain outcomes; buyer restore entries rebuild every checkpoint from exact
persisted evidence with full re-verification.

Signing is fixed inside the SDK: message signatures hash the canonical CBOR
once, hand the pre-computed digest to the Signer, normalize to low-S DER, and
are re-verified against the fixed role key before they can leave a method;
transaction signatures use the fixed MultisigPool sighash (`ForkID|All`) and
are never hashed twice. Pure Build/Read/Verify functions that need no signing
remain public pure functions and are never forced through a Workflow.

## Acceptance checks

- Role workflow constructors accept exactly one constrained signer; local
  software keys enter only via `protocol.NewPrivateKeySigner`, which rejects nil
  keys.
- No code path loads state by `RefundTemplateTxID` inside the SDK; callers supply it.
- No method performs persistence, network sends, or broadcasts, and no method
  reads a clock or queries a node height; raw transactions are returned for the
  application to submit, and every time/height judgment uses the caller's Facts.
- Static searches find no `FileStore`, `MemoryStore`, `FileQuoteStore`,
  `PoolStore`, `PendingRequestStore`, lease types, process locks, or backend
  adapters anywhere outside historical documents.
- Current wire fixtures for 001–008 and MultisigPool transactions are frozen
  byte-for-byte; wire version stays at 1.
- Stale sequence, wrong opening/role/hash, amount regressions, and expiry
  violations are still rejected, classified by stable error codes.
- English and Simplified Chinese documentation agree with the compiled API.

## Out of scope

- Any future database/file adapter as SDK work: persistence belongs to the
  application stack by design.
- Transport implementations of any kind.
- Replacing MasterSeed or MultisigPool through application configuration.
- Changing the current normative wire behavior without a new hard-switch
  specification and matching fixtures.
