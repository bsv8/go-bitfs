---
id: migrate-from-bsv8-gateway
title: Migrating from bsv8-gateway
---

# Migrating from bsv8-gateway

`go-bitfs` is now the single source of truth for the BitFS v1 file exchange, arbitration, and fee pool protocol. The current wire truth is `protocol.WireVersion = 1`, the CDDL files under `spec/v1/`, and the documents numbered 001–008; the retired pre-v1 message system lives on only under `spec/legacy/` and MUST NOT be used by new implementations.

- Remove all dependencies on `proto/bitfs/*` and its generated code; the current BitFS business wire schema is governed by the v1 CDDL and deterministic CBOR defined in 001, 003, and 004.
- Remove all dependencies on the legacy fee pool proto and gRPC generated code; the current 002, 005, 006, and 007 are governed by the v1 wire documents and the published MultisigPool transaction bytes.
- Replace local seed encoding/decoding, content hashing, ticket signing, and arbitration evidence verification with the implementations in `go-bitfs/bitfs`.
- Remove the BSE1 seed format: the seed is exclusively the sequential concatenation of 32-byte block hashes.
- Remove tail-block zero-padded hashing: all blocks MUST hash the raw bytes as actually delivered.
- The gateway, libp2p, database, policy, and daemon implement only runtime adaptations and MUST NOT define BitFS protocol truth.
