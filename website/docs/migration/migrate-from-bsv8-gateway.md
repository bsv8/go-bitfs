---
id: migrate-from-bsv8-gateway
title: Migrating from bsv8-gateway
---

# Migrating from bsv8-gateway

`go-bitfs` is now the single source of truth for the BitFS v4 file exchange, arbitration, and MultisigPool v4 fee pool protocol. The CDDL files under the directory named `spec/v1` are retained solely for historical path compatibility and MUST NOT be used for the current protocol; the current source of truth is `spec/v4` and the v4 documents numbered 001–007.

- Remove all dependencies on `proto/bitfs/*` and its generated code; the current BitFS business wire schema is governed by the v4 CDDL and deterministic CBOR defined in 001, 003, and 004.
- Remove all dependencies on the legacy fee pool proto and gRPC generated code; the current 002, 005, 006, and 007 are governed by the v4 pool/arbitration CDDL and the published MultisigPool transaction bytes.
- Replace local seed encoding/decoding, content hashing, ticket signing, and arbitration evidence verification with the implementations in `go-bitfs/bitfs`.
- Remove the BSE1 seed format: the v4 seed is exclusively the sequential concatenation of 32-byte block hashes.
- Remove tail-block zero-padded hashing: all blocks MUST hash the raw bytes as actually delivered.
- The gateway, libp2p, database, policy, and daemon implement only runtime adaptations and MUST NOT define BitFS protocol truth.
