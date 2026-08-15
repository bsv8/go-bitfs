---
id: external-hooks-and-data-types
title: 02 · External hooks and data types
---

# 02 · External hooks and data types

The SDK boundary contains infrastructure, not protocol rules. Applications
provide private-key custody, persistence, content bytes, and a narrow BSV
backend. go-bitfs owns message encoding, signature verification, pricing,
state transitions, MultisigPool v4 transaction construction, and submission
preconditions.

## Signing and key custody

pool.Signer is the only signing capability exposed to role workflows:

~~~go
type Signer interface {
    PublicKey(context.Context) ([]byte, error)
    Sign(context.Context, []byte) ([]byte, error) // DER-only signature
}
~~~

`PublicKey` must return the protocol's canonical 33-byte compressed
secp256k1 public-key encoding. Uncompressed 65-byte keys are rejected before
they can enter signed wire terms or pool evidence.

The application may implement it with a local wallet, HSM, browser wallet, or
remote signer. The SDK never accepts a private key, seed, key-export callback,
or signature-verifier callback. Role workflows always call `Sign` with one
SDK-computed 32-byte digest: canonical 001/003/004 CBOR is hashed once with
SHA-256, while pool transactions use the fixed sighash digest. `Sign` returns
DER-only bytes. The core appends protocol sighash bytes where required and
verifies the returned signature against the expected role before returning,
saving, merging, or submitting it.

The lower-level `QuoteTermsSigner` and `ContentTermsSigner` callbacks are
different: constructors pass them the exact canonical CBOR bytes. Each
callback must hash those bytes once with SHA-256, return DER-only bytes, and
the constructor fixedly re-verifies the result before returning a credential.

Public keys in a quote, opening proof, content request, or payment state are
protocol evidence. Callers must not substitute a participant verifier or
reconfigure the buyer/seller/arbiter roles.

## Storage interfaces

Quote stores are intentionally role-local so an application can use a database,
file, or replicated service without changing wire bytes:

~~~go
type QuoteStore interface {
    SaveQuote(context.Context, *bitfs.SignedFileQuote) error
    LoadQuote(context.Context, bitfs.Hash32) (*bitfs.SignedFileQuote, error)
}
~~~

pool.PoolStore retains complete opening proofs and the latest node-accepted
payment state, and provides uncertainty/reconciliation markers:

~~~go
type PoolStore interface {
    OpeningProofStore
    LoadOpeningProofByFundingTxID(context.Context, Hash32) (*OpeningProof, error)
    SaveAcceptedPayment(context.Context, *PaymentState) error
    LoadAcceptedPayment(context.Context, Hash32) (*PaymentState, error)
    EnsurePoolHealthy(context.Context, Hash32) error
    EnsurePoolOpen(context.Context, Hash32) error
    MarkPoolClosing(context.Context, Hash32) error
    ReconcilePoolClosing(context.Context, Hash32) error
    MarkExternalStateUncertain(context.Context, Hash32, Hash32) error
    ReconcileExternalState(context.Context, Hash32, *PaymentState) error
}
~~~

The seller also supplies pool.PendingRequestStore for the delivery lease. Each
lease records the spend ID, base sequence, base seller amount, authorization
hash, and expected seller delta; retries release only an exact matching lease.
Its TryAcquire, Load, and Release methods prevent two deliveries from spending
the same cumulative sequence. pool.MemoryStore is a useful single-process
implementation; pool.FileStore persists snapshots with atomic replacement and
reloads them under an advisory lock. A database may implement the same
interfaces, but it cannot change canonical transaction IDs or protocol
sequence rules. Stores do not calculate an externally supplied transaction ID:
the SDK derives IDs with its fixed BSV transaction parser.

## Content interfaces

Buyer content and seed adapters are optional because a buyer may request only
seed data or delegate payload persistence:

~~~go
type ContentSink interface {
    SaveVerifiedContent(context.Context, bitfs.Hash32, []byte) error
}
type SeedSource interface {
    LoadSeed(context.Context, masterseed.Digest) ([]byte, error)
}
~~~

The seller's ContentSource loads committed seed or block bytes:

~~~go
type ContentSource interface {
    LoadSeed(context.Context, masterseed.Digest) ([]byte, error)
    LoadBlock(context.Context, masterseed.Digest) ([]byte, error)
}
~~~

The workflows verify hashes, seed structure, block membership, content size,
quote terms, and request/delivery signatures before accepting loaded bytes or
calling SaveVerifiedContent. Content storage is therefore external, while
content proof and business pricing remain fixed in bitfs.

## Narrow BSV backend boundary

The buyer receives a raw backend that can accept only non-final pool states:

~~~go
type NonFinalPoolBackend interface {
    SubmitUpdate(context.Context, []byte) (*UpdateAcceptance, error)
    SubmitFinal(context.Context, []byte) (Hash32, error)
}
~~~

The seller receives the wider backend because it must broadcast funding before
pool updates and final settlement:

~~~go
type FundingBackend interface {
    // Same raw transaction already accepted => same canonical txid, nil error.
    SubmitTransaction(context.Context, []byte) (Hash32, error)
}

type PoolBackend interface {
    NonFinalPoolBackend
    FundingBackend
}
~~~

`SubmitTransaction` is an idempotent canonical-transaction broadcast contract:
when the exact same raw transaction was already accepted, a retry returns the
same `Hash32` and a nil error. An `already-known` response is therefore
success, not a failure. This contract makes funding uncertainty recovery safe;
it is a backend behavior, not an application callback that the workflow tries
to infer.

A backend may be an RPC, gRPC, vendor SDK, or in-process node client. It does
not assemble or validate protocol transactions. Workflows construct a
pool.VerifiedNonFinalPoolNode internally from the backend and persisted opening
proofs. That adapter dynamically creates the concrete MultisigPool engine from
each proof, validates funding/update/final bytes before delegation, and checks
returned transaction ID, spend anchor, and payment sequence after delegation.
A permissive backend therefore cannot turn malformed evidence into an accepted
workflow state.

After a backend call, an ordinary error or an acceptance whose ID/sequence
does not exactly match the candidate is treated as an uncertain external
outcome. The workflow records the candidate transaction ID with
`MarkExternalStateUncertain` and returns `ErrPoolStateUncertain`; callers must
reconcile that exact raw transaction before any new signing or submission.
`ReconcileExternalState` records the exact externally confirmed state and
clears the uncertain marker. When the same store also owns a matching pending
lease, it can atomically clear that lease after validating the complete lease
fields. If `PoolStore` and `PendingRequestStore` are separate, the 005/007
idempotent workflow retry releases the independent lease only after matching
the full cryptographic evidence. A final close also requires
`ReconcilePoolClosing` after the accepted final state is observed, so
close-issued guards survive process restart until explicitly cleared.

Funding uses ordinary broadcast semantics and is never routed through final
settlement. Block-height refund expiry is the one optional chain-state query:
a backend may implement BlockHeight(context.Context) (uint32, error). No wall
clock or expiry strategy is injected; timestamp expiry uses the captured SDK
operation time, while height refunds require an authoritative height source.

## Protocol input types

The role APIs intentionally accept protocol-shaped data rather than arbitrary
business callbacks:

- pool.OpeningInput contains raw funding bytes, pool output index, expiry lock
  time, fee rate, and seller/arbiter public keys.
- pool.RefundPresignRequest and pool.RefundPresignResponse carry 002 opening
  evidence; pool.FundingTxDelivery reveals funding only after the refund proof
  is durably recorded.
- buyer.ContentRequestInput contains quote hash, SpendTxID, a ContentRef, size,
  and deadline. The opening proof supplies the arbiter and base sequence;
  price and payment sequence are derived, not caller-controlled.
- pool.PaymentUpdate, pool.UnsignedPayment, and pool.SignedPayment distinguish
  unsigned state, detached signatures, and complete transactions.

The wire package maps these values to canonical 001–007 CBOR. Transport
(HTTP, WebSocket, queue, CLI, or browser messaging) is deliberately absent;
all environments carry the same bytes and use the same role methods.

## What is not an extension point

There is no workflow clock, transaction engine hook, opening-hook aggregate,
participant/verifier port, private-key provider, or application-supplied
transaction-ID calculator. Those abstractions would allow a caller to replace
business rules that define the protocol. Only custody, persistence, content,
and network/backend integration cross this boundary.
