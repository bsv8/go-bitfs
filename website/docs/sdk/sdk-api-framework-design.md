---
id: sdk-api-framework-design
title: BitFS SDK API framework
---

# BitFS SDK API framework

go-bitfs is the executable protocol specification for 001–008. It is a
**stateless, infrastructure-side-effect-free protocol SDK**: role workflows in
`buyer`, `seller`, and `arbiter` hold only the constrained signer fixed at
construction (`protocol.Signer`; local software keys enter through
`protocol.NewPrivateKeySigner`) and perform deterministic Build/Verify/Sign/Merge
computations over explicitly supplied inputs.

Applications provide everything else: persistence keyed by `RefundTemplateTxID`
and by authorization ID, transactions and locks, concurrency serialization,
retries and idempotency, content storage, peer transport, node broadcasting, and
multi-tenant authorization. The SDK never loads or saves state,
never reads or writes content, never broadcasts a transaction, and never
queries a node or clock — every time- or height-sensitive call receives one
explicit `protocol.Facts{Now, BlockHeight}` value, and the SDK only validates
protocol rules against those facts.

The layering is:

```text
protocol/    Shared foundations: constrained Signer port (+ NewPrivateKeySigner),
             explicit Facts, typed IDs, structured errors with ErrorCode
content/     001/003/004 credentials, seeds, hashes, pricing; immutable VerifiedQuote
pool/        002/005/006 settlement state machine and transaction engine;
             opaque verified values (VerifiedOpening, VerifiedPaymentState,
             VerifiedSignedTransaction)
arbitration/ Pure 007/008 custody-evidence domain functions (no role state)
wire/        Typed encoders and strict decoders returning immutable
             wire.Artifact values over exact bytes
buyer/, seller/, arbiter/
             Role workflows: the only recommended application entry path
```

Role workflows are the single recommended surface for applications. Domain
packages stay public for wallets, auditors, and tooling, but every ordinary
purchase should flow through the workflow methods described in
[03 · Role workflow API](role-workflow-api.md).
