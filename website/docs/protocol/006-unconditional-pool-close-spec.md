---
id: 006-unconditional-pool-close-spec
title: 006 · v3 Negotiated immediate-close specification
---

# 006 · v3 Negotiated immediate-close specification

MultisigPool v4 performs immediate close by constructing an unsigned three-output state with the final sequence and locktime; the Arbiter output remains present with amount 0. The buyer returns the unsigned transaction and a detached buyer signature. After validation, the seller produces a detached seller signature and uses `MergeArbitratedPoolBuyerSellerSignatures` to return the complete final transaction. Local accepted state MUST NOT advance before the node confirms the transaction.
