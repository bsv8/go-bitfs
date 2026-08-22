---
id: sdk-api-framework-design
title: BitFS SDK API framework
---

# BitFS SDK API framework

go-bitfs is the executable protocol specification for 001–007. It is a
**stateless, infrastructure-side-effect-free protocol SDK**: role workflows
hold only the official BSV private key passed to `WorkflowConfig{PrivateKey}`
and perform deterministic Build/Verify/Sign/Merge
computations over explicitly supplied inputs.

Applications provide everything else: persistence keyed by `RefundTemplateTxID`,
transactions and locks, concurrency serialization, retries and idempotency,
content storage, peer transport, node broadcasting, chain-height sources, time
sources, and multi-tenant authorization. The SDK never loads or saves state,
never reads or writes content, never broadcasts a transaction, and never
queries a node or clock — every public entry point reads system UTC once
internally, block heights arrive as explicit `blockHeight uint32` parameters,
and the SDK only validates protocol rules against those facts.
