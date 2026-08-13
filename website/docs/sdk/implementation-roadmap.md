---
id: implementation-roadmap
title: 04 · Implementation roadmap
---

# 04 · Implementation roadmap

Return to the [SDK API framework](sdk-api-framework-design.md).

1. `wire`, 001/003/004 in `bitfs`, 002/005/006 in `pool`, and 007 in `arbitration` implement deterministic CBOR, strict decoding, and evidence validation.
2. MultisigPool is the sole implementation of payment-pool transactions, `SIGHASH_ALL|FORKID`, 2-of-3 scripts, cumulative payments, final close, and refund-expiry checks. `pool.VerifiedNonFinalPoolNode` binds local validation to backend responses; callers inject a concrete BSV RPC through `NonFinalPoolBackend`.
3. `pool.MemoryStore` and `bitfs.FileQuoteStore` provide thread-safe or restart-safe reference persistence. Multi-process production deployments should use a transactional database while retaining atomic update, immutability, and idempotency guarantees.
4. End-to-end tests cover `buyer.Workflow`, `seller.Workflow`, and `arbitration.Workflow`, including quote, pool opening, content delivery, payment advancement, and duplicate-payment retry.
5. The current surface contains only BitFS v3 role workflows and `pool` role adapters. The former `settlement`/runtime dual stack has been removed; there is no legacy build-tag acceptance path.
