---
id: implementation-roadmap
title: 04 · Implementation roadmap
---

# 04 · Implementation roadmap

Return to the [SDK API framework](sdk-api-framework-design.md).

1. `wire`, 001/003/004 in `bitfs`, 002/005/006 in `pool`, and 007 in `arbitration` implement deterministic CBOR, strict decoding, and evidence validation.
2. MultisigPool is the sole implementation of payment-pool transactions, `SIGHASH_ALL|FORKID`, 2-of-3 scripts, cumulative payments, final close, and refund-expiry checks. Refund expiry verification reads system UTC once internally and takes the caller-provided block height explicitly; the SDK has no node access.
3. Role workflows (`buyer`, `seller`, `arbitration`) hold only the official BSV private key from `WorkflowConfig{PrivateKey}`. Every method takes explicit inputs (quote, opening proof, previous payment state, delivery context, content bytes, seed, block height) and returns only computed wire messages, raw transactions, verified evidence, and local role state for the application to persist.
4. End-to-end tests cover the full 001–007 lifecycle with the test acting as the application: all intermediate states are held in test variables and passed explicitly into every call.
5. The SDK ships no storage adapters. Production deployments implement persistence, serialization, outbox patterns, and node reconciliation in their own stack; these are application concerns by design, not future SDK work items.
