---
id: bitfs-arbitration-settlement-v1
title: BitFS Arbitration and 2-of-3 Settlement Specification v1
---

# BitFS Arbitration and 2-of-3 Settlement Specification v1

> **Historical compatibility document, not to be used as a basis for new construction.** The `HashGetTicket`, `session_id`, server-side records, `proposal_id`, arbitration final amounts, and signature domains described herein belong to the legacy V1 design. The current design is governed by [001-Quote Credential Spec](../protocol/001-quote-credential-spec.md) through [006-Unconditional Pool Close Spec](../protocol/006-unconditional-pool-close-spec.md); notably, the V1 close path does not define arbitration amounts within the pool.

Arbitration is a core part of BitFS transactions. It is accomplished jointly by two protocol layers, both provided by `go-bitfs`.

## Code Roles

Both `buyer` and `seller` are full transaction roles. The two collaborate through independent `FileQuote`, `HashGetTicket`, and `HashDelivery` asynchronous CBOR messages; queues, WebSocket, TCP, or libp2p adapters are only responsible for delivery and do not alter business messages.

`arbiterclient` is a local port wrapper for the arbitration workflow. `demo/arbiter` is the minimal handler implementation provided by this repository, specifically designed to validate the standard arbitration flow; it uses in-memory records and MUST be injected with a session mapping, pool client, and both arbitration signers by the caller. It MUST NOT be used as a production arbitration node.

## BitFS Business Arbitration

`ArbitrationClaim` is the dispute evidence. A seller claim MUST carry the buyer-signed `HashGetTicket` along with the actual payload; the arbiter MUST sequentially verify the ticket signature, session, expiration, delivery length, and `sha256(payload) == ticket.content_hash`. The ticket's `sequence` MUST correspond to a payment position that the current fee pool can still arbitrate.

A buyer claim MAY omit the payload. If the arbiter recovers a matching payload from the seller or from existing records, it SHOULD publish it to the buyer via `ArbitrationDecision.recovered_payload` before proceeding with fund settlement.

Once a seller session enters arbitration, that seller session is finalized and MUST NOT continue normal trading. The `ArbitrationRecord` state serves as the arbitration ground truth across service restarts.

## 2-of-3 Fund Settlement

The fund pool uses a 32-byte `spend_txid` as the primary key; BitFS's `session_id` MUST NOT enter the pool wire schema. At runtime, a `(bitfs_session_id, seller_pubkey) -> spend_txid` mapping is maintained. The normal path is advanced by buyer + seller for payment; the dispute path is completed by the arbiter together with the party corresponding to the ruling direction.

`settlement.ArbitrationRequest` is the fund arbitration entry point. It signs over the `spend_txid`, ruling direction, reason, and final payment amount, and completes the two-phase close through the asynchronous `CloseSignatureRequest`, `CloseSignature`, and `PoolArbitrated` messages. Transactions and transaction IDs are raw `bstr`, not hex strings.

BitFS business rulings and pool fund signatures use different signing domains and MUST NOT be used interchangeably.
