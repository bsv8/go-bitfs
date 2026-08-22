---
id: core-boundary-refactor-work-order
title: Core boundary refactor work order
---

# Core boundary refactor work order

This page records the acceptance contract of the completed SDK boundary hard
switch. It supersedes every earlier description in which role workflows could
accept stores, content sources/sinks, or BSV submission backends. Protocol
specifications 001–007 remain authoritative for wire bytes and protocol
behavior; the v4 wire shape, CDDL, signature domains, and `RefundTemplateTxID`
algorithm are unchanged.

## Product definition

`go-bitfs` is a **stateless, infrastructure-side-effect-free** executable BitFS
protocol specification and role SDK for Buyer, Seller, and Arbiter
implementations. Given explicit protocol inputs and explicit prior state, it
strictly decides whether the inputs are legal and computes the next protocol
message, transaction, signature material, or local role state.

The application owns everything the SDK no longer does:

- databases, files, transactions, locks, CAS, and unique constraints;
- concurrency serialization per `RefundTemplateTxID` (the SDK has no mutex or lease);
- retries, idempotency, crash recovery, and outboxes;
- peer transport, routing, timeouts;
- node broadcasting, chain queries, and result reconciliation — only the
  application's node adapter may declare that a broadcast was accepted;
- block-height sources, supplied explicitly as `blockHeight uint32` arguments;
  the SDK reads system UTC once internally per public entry point and
  validates locktime rules against those facts;
- content repositories: bytes are read before a call and passed in; verified
  bytes are returned as data and saved by the application;
- multi-tenant authorization (`RefundTemplateTxID` is a routing ID, not an auth token).

MasterSeed remains the fixed content-proof implementation. MultisigPool v4
remains the fixed BSV pool-transaction implementation. Neither is an
application plugin.

## Required public boundary

Role workflow constructors accept exactly one capability:

~~~go
type WorkflowConfig struct {
    PrivateKey *ec.PrivateKey // official BSV Go SDK private key
}
~~~

No store, quote store, pending-request store, content sink/source, backend,
node adapter, clock, signer port, verifier strategy, or locker field exists.
Every method takes its business
inputs explicitly (quote, opening proof, previous payment state, delivery
context, content bytes, seed, block height) and returns only computed wire
messages, raw transactions, verified evidence, and local role state such as
`buyer.BuyerOpeningState` or `seller.ContentDeliveryState`. Methods never load,
save, send, broadcast, or mark uncertain outcomes.

Signing is not a hook: it always uses the constructor-supplied official BSV
private key through the SDK's fixed implementations. Message signatures hash
the canonical CBOR once with SHA-256, sign the pre-computed digest with
`(*ec.PrivateKey).Sign`, normalize to low-S DER, and are re-verified by a fixed
verifier against the derived role key before they can leave a method;
transaction signatures use the fixed MultisigPool sighash (`ForkID|All`) and
are never hashed twice. Pure Build/Read/Verify functions that need no signing
remain public pure functions and are never forced through a Workflow.

## Acceptance checks

- `buyer.WorkflowConfig`, `seller.WorkflowConfig`, and
  `arbitration.WorkflowConfig` contain nothing but `PrivateKey`, and the
  constructors reject nil keys.
- No code path loads state by `RefundTemplateTxID` inside the SDK; callers supply it.
- No method performs persistence, network sends, or broadcasts; raw
  transactions are returned for the application to submit.
- Static searches find no `FileStore`, `MemoryStore`, `FileQuoteStore`,
  `PoolStore`, `PendingRequestStore`, lease types, process locks, or backend
  adapters anywhere outside historical documents.
- Wire fixtures for 001–007 and MultisigPool transactions are byte-identical
  before and after the switch; `MajorVersion == 4` with no v5.
- Stale sequence, wrong opening/role/hash, amount regressions, and expiry
  violations are still rejected.
- English and Simplified Chinese documentation agree with the compiled API.

## Out of scope

- Any future database/file adapter as SDK work: persistence belongs to the
  application stack by design.
- Transport implementations of any kind.
- Replacing MasterSeed or MultisigPool through application configuration.
- Changing the normative 001–007 wire behavior.
