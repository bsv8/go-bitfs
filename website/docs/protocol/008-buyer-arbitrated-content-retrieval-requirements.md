---
id: 008-buyer-arbitrated-content-retrieval-requirements
title: 008 · Buyer arbitrated content retrieval requirements
---

# 008 · Buyer arbitrated content retrieval requirements

## Business goal

When Seller and Buyer cannot connect directly but both can reach the Arbiter,
the Buyer must be able to recover the exact custodied content of a completed
007 arbitration without inventing per-application download tokens or HTTP
fields. The recovery path is a simple, offline-verifiable chain:

```text
Buyer original OpeningProof + Buyer original signed 003
  -> independently build the Seller's exact ClaimCBOR
  -> ArbitrationClaimID
  -> content_retrieval_request_cbor = [arbitration_claim_id, retrieval_nonce]
     signed via SignWireDocument(1, 10, ...)
  -> Arbiter looks up custody by Claim ID and verifies everything
  -> Buyer independently verifies the Arbiter-signed Kind 11 result and payload
```

## Hard boundaries

The protocol MUST NOT provide buyer arbitration close. There is no
Buyer+Arbiter close candidate, no challenge window, no fast refund, and no
"the arbiter could not find a claim, so it spends the pool output for the
buyer" rule. If the seller is unreachable or refuses to negotiate, the buyer
waits until `nLockTime` matures and broadcasts the presigned RefundTx from
002. The only current truths remain: negotiated close via 006, or refund
broadcast after expiry.

## SDK responsibilities

The SDK MUST:

- build the ClaimCBOR/ArbitrationClaimID through one shared builder used by
  both the seller 007 path and the buyer 008 path;
- encode/decode Kind 10/11 with strict deterministic CBOR and derived size
  limits (334 bytes / branch-derived maximum);
- sign `content_retrieval_request_cbor = [arbitration_claim_id,
  retrieval_nonce]` through the unified `SignWireDocument(1, 10, ...)` helper
  and self-verify immediately;
- verify stored Kind 8/9 evidence chains without reading any clock: both
  child signatures, ArbitrationClaimID equality across Kind 10 / Kind 8 /
  Kind 9, payload count/order/hashes, and the Arbiter transaction signature
  over the rebuilt candidate;
- require the Kind 10 request to name the locally rebuilt
  ArbitrationClaimID and carry this buyer's unified signature over the exact
  request document, so no embedded Claim bytes are needed or trusted;
- re-check payload membership, protocol lengths, aggregate pricing, and
  previous-state continuity during acceptance;
- return deep copies only.

The SDK MUST NOT add stores, repositories, HTTP clients/servers, nonce
caches, random sources, clock injection, nodes, broadcasters, or retention
schedulers.

## Application responsibilities

The application MUST:

- locate a reachable arbiter endpoint by public key;
- generate the 32-byte nonce from a cryptographic random source;
- persist exact Kind 10 before sending, and exact Kind 11 plus payloads after
  acceptance;
- look up its custody store by Claim ID and require exact Kind 8 AND exact
  Kind 9 before serving payloads (`CustodyPrepared` records answer the signed
  not_ready branch after buyer authentication against the stored Kind 8);
- atomically occupy unique (Claim ID, Nonce) — database unique key,
  transaction/CAS, or equivalent — strictly after signature verification, so
  failed-signature requests never pollute the nonce table; the not_ready and
  custody_gone branches occupy the nonce exactly like the available branch;
- persist the FIRST signed answer per content_retrieval_request_id and resend
  it verbatim on replay: a captured not_ready request must never be upgraded
  to an available authorization after the record turns ready — the buyer MUST
  retry with a fresh nonce;
- treat `seller_arbitration_not_received` as the single explicit exception:
  no Claim means no buyer authentication is possible, so that answer occupies
  nothing and persists nothing, but the endpoint MUST rate-limit such queries
  and return no record metadata;
- answer the three honest negative results as Arbiter-signed four-element
  Kind 11 unavailable branches (`seller_arbitration_not_received` /
  `seller_arbitration_not_ready` / `custody_gone`), while handling
  Unauthorized / Malformed / RateLimited / internal storage errors on the
  transport/business error channel, never disguised as structured Kind 11;
- protect requests and responses with TLS or an equivalently secure transport;
  the nonce does not substitute for confidentiality;
- define and publish retention policy; within retention a buyer may download
  repeatedly using fresh nonces, and retention ending with safe deletion is
  answered by the signed custody_gone branch — cached first answers are
  deleted together with the content;
- keep old nonce records at least as long as the corresponding custody record
  exists so an old signed request cannot become replayable again;
- log neither raw payloads, private keys, nor complete replayable requests;
  audit logs use Claim ID / nonce hashes and state only.

## Retry semantics

- The nonce is the replay key for one request, not a long-lived token.
- The arbiter occupies (Claim ID, Nonce) atomically after buyer authentication
  for `not_received`-excepted branches (`not_ready`, `custody_gone`,
  `available`) and persists the first signed Kind 11 as that request's only
  answer.
- Replaying the same content_retrieval_request_id returns that first persisted
  response byte-for-byte; a status change never upgrades or re-evaluates it.
- After a network timeout or an incomplete transfer the buyer first RESENDS
  the same exact Kind 10: the replay is idempotent and returns the first
  persisted Kind 11 byte-for-byte. Only after explicitly receiving a
  `not_ready` answer does the buyer generate a new nonce and a new Kind 10
  signature; the arbiter never upgrades an old nonce into fresh content.
- Concurrent identical (Claim ID, Nonce) requests resolve to exactly one
  winner inside one atomic commit; every concurrent loser reads and returns
  the winner's persisted exact Kind 11 — the Buyer never sees a transient
  occupancy error.
- Expired quotes/deadlines/refunds do not reject already signed evidence;
  time gates were applied before Kind 9 was ever signed.
- If saving retrieved content fails, the batch is not marked complete; the
  buyer replays the same exact Kind 10 to fetch the persisted Kind 11 again
  until its own atomic save succeeds.

## Acceptance checklist

- [ ] Only records whose exact Kind 8 + exact Kind 9 both persist serve payloads.
- [ ] The Claim ID routes the lookup; a mismatched Kind 10 Claim ID is invalid evidence, never a fuzzy search key.
- [ ] Every retrieval carries a valid Buyer signature under the key recovered from the stored Claim.
- [ ] A Claim ID alone authorizes nothing.
- [ ] The available attachment binds the verified evidence bundle through content_payloads_id; payloads appear once and there is no second receipt copy.
- [ ] A replayed request returns its first persisted Kind 11 verbatim, in every branch.
- [ ] No 005, no close transaction, no broadcast side effect exists anywhere in this path.
