# BitFS CBOR Protocol v1

> **Historical compatibility schema.** The `FileQuote` / `HashGetTicket` / `HashDelivery` model below is retained only for existing V1 code. New protocol construction follows `docs/001-*` through `docs/006-*`; it must not mix this session-based ticket model with the new self-proving voucher chain.

`bitfs.cddl` is the normative wire schema.  This document defines constraints
that CDDL cannot express.

## Encoding

- A packet is exactly one CBOR data item, encoded using RFC 8949 core
  deterministic encoding.
- Every top-level and nested array uses definite length. Maps, tags, floats,
  simple values other than booleans, and indefinite-length values are invalid.
- Decoders MUST reject bytes that do not exactly equal the deterministic
  re-encoding of the decoded packet.
- V1 is a fixed schema. Unknown message kinds, wrong array lengths, and extra
  array elements are invalid. Incompatible changes require a new major version.
- `payload` is raw bytes and MUST NOT exceed 262144 bytes.

## Stable identifiers and signatures

- `packet_id` is `sha256` of the canonical CBOR bytes of the packet.
- `content_hash` is `sha256(payload)`.
- `ticket_id` is the SHA-256 digest of the domain-separated canonical unsigned
  ticket array. It excludes `buyer_signature`.
- A buyer signs the same unsigned ticket bytes used to create `ticket_id`.
  Protobuf serialization is never used as a signature input.

## Transfer constraints

- Every `seed_hash`, `content_hash`, and `ticket_id` is exactly 32 bytes.
- A seed ticket has `content_index = -1`; its `content_hash` equals
  `root_seed_hash`, and `expected_size` is divisible by 32.
- A block ticket has `content_index >= 0` and `0 < expected_size <= 262144`.
- A delivery matches a ticket only when `session_id`, `sequence`, and
  `content_hash` match, and `sha256(payload) == content_hash`.
