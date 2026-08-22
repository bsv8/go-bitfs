---
id: external-hooks-and-data-types
title: 02 · External hooks and data types
---

# 02 · External hooks and data types

The SDK is a stateless protocol library: it owns message encoding, signature
verification, pricing, transaction construction, and protocol validation, while
the calling application owns persistence, concurrency, content storage,
transport, node broadcasting, and block-height sources. The SDK accepts **no
runtime hooks at all**. There is no Signer interface, no Verifier callback, no
Clock/`NowFunc`, no Store, and no node hook; every external fact crosses the
boundary as an explicit method input or returned result.

## Signing and key custody

The only signing capability in the SDK is the official BSV private key that the
application passes as a constructor parameter:

~~~go
import ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

type WorkflowConfig struct {
    // Official BSV Go SDK private key parsed by the caller.
    PrivateKey *ec.PrivateKey
}
~~~

`buyer.WorkflowConfig`, `seller.WorkflowConfig`, and
`arbitration.WorkflowConfig` all have exactly this shape. TypeScript callers use
the native `PrivateKey` from `@bsv/sdk`. The constructor rejects a nil key, and
the compressed secp256k1 public key derived from it becomes the workflow's
role-bound identity: every later method re-checks that supplied opening evidence
belongs to this key's role before computing anything.

There is no `pool.Signer` interface to implement and no wallet, HSM, or remote
signing service adapter to provide. The SDK never accepts a seed,
key-export callback, or signature-verifier callback either. Every message
signature follows one fixed path: canonical 001/003/004 CBOR is hashed once
with SHA-256, the official private key signs that pre-computed digest, and the
low-S DER result is re-verified by a fixed internal verifier before it can be
returned. In Go, `(*ec.PrivateKey).Sign` receives the already-computed digest;
in TypeScript, `PrivateKey.sign(message)` hashes the message itself, so
cross-language test vectors must avoid hashing twice. Transaction signatures
always use the fixed MultisigPool sighash (`ForkID|All`) and are never hashed a
second time.

Public keys in a quote, opening proof, content request, or payment state are
protocol evidence. Callers cannot replace participant verification or
reconfigure the buyer/seller/arbiter roles: verification is fixed and not
substitutable.

## Persistence belongs to the application

There is no Store interface in the SDK. Workflows return local role state —
for example `buyer.BuyerOpeningState`, `seller.SellerPresignResult.Opening`,
`seller.ContentDeliveryState`, and every `pool.PaymentState` — and require that
state again as an explicit argument in later steps. Applications persist these
values in their own database keyed by `RefundTemplateTxID`, serialize concurrent work
per pool, and implement retries, outboxes, and crash recovery themselves. The
SDK adds no locks, leases, mutexes, or process-serialization of any kind:
calling the same method twice concurrently yields two independently valid
results, and deduplication is an application responsibility.

## Content bytes are caller-supplied

The seller reads seed/block bytes from its own storage and passes them via
`seller.ContentDeliveryInput`; the buyer passes verified seeds via
`buyer.ContentRequestInput.Seed` / `buyer.ContentDeliveryInput.Seed`. The
workflows verify hashes, seed structure, block membership, content size, quote
terms, and request/delivery signatures against those explicit bytes.
AcceptDelivery returns the verified payload as data (`buyer.VerifiedDelivery.Payload`);
saving it to final storage is the application's job, and a failed save means the
business step must not be treated as complete.

## Time and height facts

The SDK has no clock injection and no node access, and it takes no `now`
parameters. Every public operation entry point reads `time.Now().UTC()` exactly
once internally and reuses that reading for all expiry and locktime rules in the
call. Block heights always arrive from the caller as explicit parameters (for
example `blockHeight uint32`); the SDK never queries a node for the current
height. A height-source outage must delay or reroute refund operations, never
fabricate a value.

## Protocol input and result types

The role APIs accept protocol-shaped data and return computed results:

- pool.OpeningInput contains raw funding bytes, expiry locktime, fee rate, and
  seller/arbiter public keys.
- pool.RefundPresignRequest and pool.RefundPresignResponse carry 002 opening
  evidence; pool.FundingTxDelivery reveals funding only after the refund proof
  is durably recorded by the application.
- buyer.PreparePoolOpening returns PoolOpeningPreparation\{Request,
  *BuyerOpeningState\}: save State before sending Request. AcceptRefundPresign
  takes that saved state back explicitly and returns
  RefundPresignAcceptance\{Reference, Opening, InitialPayment\}.
- seller.PresignPoolOpening returns SellerPresignResult\{Response, Opening\}:
  save Opening before sending Response. AcceptPoolFunding takes the saved proof
  plus the delivery and returns PoolFundingAcceptance\{Opening, InitialPayment,
  FundingTx\}; broadcasting FundingTx is the application's node adapter's job.
- seller.BuildContentDelivery returns the wire delivery plus
  ContentDeliveryState — the lock-free protocol context (refund correlation ID,
  request hash, base sequence, base seller amount, expected delta) needed later
  by AcceptPayment. It carries no owner, lease, or expiry semantics.
- buyer.AcceptDelivery returns VerifiedDelivery\{Payload, Update\}: verified
  content bytes plus the signed 005 wire update.
- pool.PaymentUpdate, pool.UnsignedPayment, and pool.SignedPayment distinguish
  unsigned state, detached signatures, and complete transactions. Build/Verify/
  Accept methods return raw transactions for the application to broadcast;
  nothing is ever named "submitted" or "accepted" inside the SDK.

The correlation field across these types is `pool.RefundTemplateTxID` — a
dedicated `[32]byte` type carrying the canonical TxID of the refund template
transaction without embedded role signatures (CDDL label
`refund-template-txid`). It is not a SHA-256 of raw bytes, not a byte-reversed
hash, and not the txid of the final broadcast refund transaction.

The wire package maps these values to canonical 001–007 CBOR. Transport
(HTTP, WebSocket, queue, CLI, or browser messaging) is deliberately absent;
all environments carry the same bytes and use the same role methods.

## What is not an extension point

There is no signer port, verifier strategy, workflow clock, store/repository
hook, transaction engine hook, lease or locker, content source/sink, backend
port, private-key provider, or application-supplied transaction-ID calculator.
Those abstractions would allow a caller to replace business rules that define
the protocol, or would smuggle infrastructure side effects back into the SDK.
Only key custody crosses this boundary, once, at construction time via
`WorkflowConfig{PrivateKey}`; everything else flows through explicit inputs and
outputs.
