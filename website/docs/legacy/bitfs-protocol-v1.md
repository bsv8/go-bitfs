---
id: bitfs-protocol-v1
title: BitFS Protocol Specification v1
---

# BitFS Protocol Specification v1

> **Historical compatibility document; not to be used as a basis for new implementation.** The `FileQuote`, `HashGetTicket`, `session_id`, `content_index`, `expected_size`, ticket pricing, and signing domains described in this document belong to the legacy V1 session model. The new design follows business order and is governed by [001-Quote Credential Spec](../protocol/001-quote-credential-spec.md) through [006-Unconditional Pool Close Spec](../protocol/006-unconditional-pool-close-spec.md); new implementations MUST NOT mix the two sets of fields or treat the session ID in this file as a source of truth.

This document describes the business rules of BitFS. The wire schema is governed by [`https://github.com/bsv8/go-bitfs/tree/main/spec/v1/bitfs.cddl`](https://github.com/bsv8/go-bitfs/tree/main/spec/v1/bitfs.cddl); encoding, stable ID, and signing rules are governed by [`https://github.com/bsv8/go-bitfs/tree/main/spec/v1/protocol.md`](https://github.com/bsv8/go-bitfs/tree/main/spec/v1/protocol.md). Buyers, sellers, arbitrators, and their runtimes MUST NOT copy or alter these rules independently.

## File Model

- Each block has a fixed upper limit of `262144` bytes; the last block MAY be shorter.
- Each block's hash is fixed as `sha256(raw_block_bytes)`; the last block MUST NOT be zero-padded.
- The seed is the sequential concatenation of all block hashes: `seed_bytes = hash[0] || hash[1] || ... || hash[n-1]`.
- Each block hash is a 32-byte raw digest. Therefore, the seed for a two-block file is exactly 64 bytes; the seed does not contain a BSE1 header, version, file size, block count, or any other metadata.
- `seed_hash = sha256(seed_bytes)`.

## Discovery and Quotation

Discovery is not part of the BitFS core protocol. DHT, pubsub, trackers, or manual connections MAY use `seed_hash` to discover peers, but their addresses, ports, broadcasts, and anti-abuse rules MUST NOT enter the BitFS wire schema.

> The `FileQuote` in this section is a legacy unsigned message retained for V1 compatibility. New one-to-one, self-proving quotations MUST use `SignedFileQuote` as defined in [001-quote-credential-spec.md](../protocol/001-quote-credential-spec.md).

The seller quotes a complete file corresponding to a single `seed_hash` using the `FileQuote` CBOR message. The quotation MUST include the seed price, regular block price, last block price, file size, suggested filename, and expiration time. If the file size is evenly divisible by the block size, `endblock_price_sat` MUST equal `block_price_sat`.

## Session

A BitFS seller session MUST bind `session_id`, `seed_hash`, the buyer's public key, and the seller's public key. All subsequent hash-to-payload purchases occur within this session; a block hash MUST NOT be used to re-enter the discovery flow.

## Purchase and Delivery

The sole ticket object is `HashGetTicket`; there are no separate seed/block message sets. `content_index = -1` denotes the seed; non-negative values denote block sequence numbers. A single ticket authorizes exactly one `content_hash` and one `price_sat`.

`expected_size` is the byte count of the actual delivered payload: for the seed it is `block_count * 32`; for a regular block it is `262144`; the last block MAY be smaller. The `content_hash` of a seed ticket MUST equal `root_seed_hash`.

The seller publishes an independent `HashDelivery` asynchronous message. The buyer MUST first verify:

```text
sha256(payload) == ticket.content_hash
```

and confirm that the session, sequence, and content hash match the ticket before being allowed to proceed with payment.

## Ticket Signing

The buyer's signature covers the deterministic binary encoding of the following fields: `session_id`, `sequence`, `root_seed_hash`, `content_hash`, `content_index`, `expected_size`, `price_sat`, `buyer_pubkey`, `seller_pubkey`, `expires_at_unix`.

Encoding uses the domain separator `bitfs.ticket.v1`, signature version byte `1`, and deterministic CBOR; the concrete implementation is governed by `bitfs.HashGetTicketSigningPayload`. The signature does not cover `buyer_signature` itself.

## Normal Payment Sequence

1. The buyer creates or restores a 2-of-3 pool for the current seller session.
2. The buyer publishes a ticket; the seller asynchronously verifies it and publishes a delivery message.
3. The buyer receives the delivery message and validates the payload hash.
4. Only after successful validation does the buyer prepare and commit the ticket payment.
5. Only after a successful commit may the ticket be marked as paid.

A buyer MAY purchase different blocks from multiple sellers, but each seller session MUST bind to exactly one independent 2-of-3 fee pool.
