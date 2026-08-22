---
id: 006-unconditional-pool-close-spec
title: 006 · v4 Negotiated immediate-close specification
---

# 006 · v4 Negotiated immediate-close specification

MultisigPool v4 performs immediate close by constructing an unsigned three-output state with the final sequence and locktime; the Arbiter output remains present with amount 0. The buyer returns the unsigned transaction and a detached buyer signature. After validation, the seller produces a detached seller signature and uses `MergeArbitratedPoolBuyerSellerSignatures` to return the complete final transaction. Local accepted state MUST NOT advance before the node confirms the transaction.

There is no standalone wire 006 container: both roles address the pool exclusively by its `RefundTemplateTxID` correlation ID in public inputs and in whatever application-local records the caller keeps (the SDK holds none). The node submission interface keeps using raw transactions and real on-chain txids; the correlation ID never impersonates an on-chain txid. If a separately deliverable 006 message is ever added, its first business field MUST be `refund_template_txid`.
