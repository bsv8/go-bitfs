---
id: 004-content-delivery-spec
title: 004 · v3 Content delivery credential specification
---

# 004 · v3 Content delivery credential specification

004 uses protocol major 3, references the `PaymentAuthorizationHash` from 003, and carries the content bytes. The seller signs deterministic CBOR delivery terms. Before constructing the unsigned 005 state or producing its detached signature, the buyer MUST verify the content hash, quoted price, expiry, and seller identity.
