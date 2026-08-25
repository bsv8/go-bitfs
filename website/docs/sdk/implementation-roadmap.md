---
id: implementation-roadmap
title: 04 · Implementation roadmap
---

# 04 · Implementation roadmap

Return to the [SDK API framework](sdk-api-framework-design.md).

The hard switch described on this page is **complete**; the statements below
describe the shipped state, not future plans.

1. `wire` returns immutable exact-bytes Artifacts from typed encoders and strict decoders for all eleven kinds; 001/003/004 live in `content`, 002/005/006 in `pool`, and 007/008 custody evidence in `arbitration` — deterministic CBOR, strict decoding, and evidence validation are done.
2. MultisigPool is the sole implementation of payment-pool transactions, `SIGHASH_ALL|FORKID`, 2-of-3 scripts, cumulative payments, final close, and refund-expiry checks. Refund expiry verification takes the caller's explicit time and block height per call through `protocol.Facts`; the SDK has no node access and no clock read.
3. Role workflows (`buyer`, `seller`, `arbiter`) hold only the constrained signer fixed at construction (`protocol.NewPrivateKeySigner` is the only entry for local software keys). Every method takes explicit inputs (verified quote, pool checkpoint, delivery context, content bytes, seed) plus one explicit Facts value and returns only computed Artifacts, raw transactions wrapped in verified values, verified evidence, and opaque checkpoints for the application to persist.
4. End-to-end tests cover the full 001–008 lifecycle with the test acting as the application: all intermediate states are held in test variables and passed explicitly into every call; a documented-API smoke test compiles the README-style main-path snippets so the guide cannot drift from real signatures.
5. The SDK ships no storage adapters. Production deployments implement persistence, serialization, outbox patterns, and node reconciliation in their own stack; these are application concerns by design, not future SDK work items.
