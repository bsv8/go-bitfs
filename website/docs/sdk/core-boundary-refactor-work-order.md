---
id: core-boundary-refactor-work-order
title: Core boundary refactor work order
---

# Core boundary refactor work order

This work order is the acceptance contract for the SDK boundary refactor. It is
normative for the implementation work described here; protocol specifications
001–007 remain authoritative for wire bytes and protocol behavior.

## Product definition

`go-bitfs` is the executable BitFS protocol specification and the role SDK for
Buyer, Seller, and Arbiter implementations. It owns deterministic message
construction, strict reading, semantic verification, protocol calculations,
and the 001–007 state transitions.

The application owns only infrastructure:

- persistence and atomic storage operations;
- public-key lookup and signing of exact SDK-supplied bytes or digests, without
  any required key-vault product or private-key export;
- peer-to-peer message transport, which is completely outside this SDK;
- concrete BSV-node connectivity behind narrow submission backends;
- content byte storage behind seed/block source and sink interfaces.

MasterSeed is the fixed content-proof implementation. MultisigPool v4 is the
fixed BSV pool-transaction implementation. Neither is an application plugin or
a replaceable workflow port.

## Required public boundary

Role workflow constructors may accept stores, signers, content sources/sinks,
and BSV submission backends. They must not accept replaceable implementations
for any of the following:

- deterministic CBOR encoding or strict decoding;
- signature verification;
- participant verification;
- transaction ID calculation;
- MultisigPool construction, parsing, fee calculation, signature-role checks,
  signature merging, pool-capacity checks, or refund-expiry rules;
- BitFS pricing, authorization hashes, sequence derivation, or state-machine
  decisions.

The ordinary Buyer, Seller, and Arbiter constructors must not expose `Clock`.
Production workflows use the SDK's canonical UTC Unix-second rules and system
time. Explicit `...At` pure verification functions may remain public for
replay, conformance vectors, and boundary tests.

The signing hook is a basic operation and must not return a private key. The
SDK or MultisigPool adapter constructs the exact message or transaction digest,
asks the hook to sign it, normalizes any protocol-required sighash byte itself,
and verifies the returned signature before accepting or persisting it.

No role workflow may know an HTTP endpoint, WebSocket, libp2p peer, queue, CLI,
or browser transport. It returns and consumes typed protocol messages and the
existing deterministic wire encodings. BSV submission hooks express acceptance
semantics, not transport protocols, and SDK code validates both the submitted
transaction and the returned acceptance identity.

## Implementation tasks

1. Replace `PrivateKeyProvider` transaction signing with the external basic
   `Signer` operation. No exported production API may return `*ec.PrivateKey`.
2. Make role workflows construct and use the repository's concrete
   MultisigPool engine/adapters from the participant keys in the current quote,
   opening request, or opening proof. Remove injectable Buyer/Seller/Arbiter
   transaction ports and participant verifiers from workflow configuration.
3. Fold pool-opening verification and transaction-ID calculation into that
   concrete engine. Replace opening-hook aggregates with storage and BSV
   submission dependencies only. Every generated signature and complete proof
   must be verified by the core before persistence or return.
4. Make standard ECDSA verification a core implementation detail. Remove
   quote/content/authorization verifier callbacks from role workflow
   configuration while retaining pure lower-level verification APIs where they
   are useful to protocol users.
5. Remove public workflow `Clock` configuration. Preserve deterministic `At`
   verification entry points and update tests to exercise exact expiry
   boundaries without changing the production constructor surface.
6. Keep peer transport absent. Keep BSV backends narrow and ensure the core
   verifies transaction bytes before submission and verifies txid, spend
   anchor, and sequence after non-final acceptance.
7. Preserve strict Build/Read/Verify behavior for all 001–007 messages. Inputs
   must not ask applications to repeat price, sequence, participant, fee, or
   hash values that the SDK can derive from verified evidence.
8. Update integration tests, package tests, examples, generated API comments,
   and both website languages to describe only the new boundary. Remove all
   production references that call transaction engines or verifiers external
   hooks.

## Acceptance checks

- `go test ./...` passes, including the normal purchase, retry, close, refund,
  and Seller+Arbiter settlement paths.
- A test signer can implement the complete flow with `PublicKey` and `Sign`
  only; it never exposes an EC private key.
- Buyer, Seller, and Arbiter workflow configs contain no `Clock`, generic
  signature verifier, participant verifier, opening-hook aggregate, or
  replaceable transaction-engine port.
- Deliberately malformed opening, payment, close, and arbitration bytes are
  rejected by the fixed core even when storage and BSV backends behave
  permissively.
- Signing-hook output is checked for the expected role before it is returned,
  persisted, merged, or submitted.
- There is no peer transport implementation or transport-specific field in the
  public protocol and role-workflow API.
- English and Simplified Chinese documentation agree with the compiled API.

## Out of scope

- Implementing HTTP, WebSocket, libp2p, queue, CLI, or browser transport.
- Binding the signer hook to KeyHold or any other custody product.
- Replacing MasterSeed or MultisigPool through application configuration.
- Designing a new wire protocol or changing the normative 001–007 business
  behavior unless a current implementation bug makes that necessary.
