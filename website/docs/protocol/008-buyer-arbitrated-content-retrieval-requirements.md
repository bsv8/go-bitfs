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
  -> [ClaimID + random nonce] signed by the Buyer
  -> Arbiter looks up custody by ClaimID and verifies everything
  -> Buyer independently verifies Claim, Receipt, transaction signature, payload
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

- build the ClaimCBOR/Claim ID through one shared builder used by both the
  seller 007 path and the buyer 008 path;
- encode/decode Kind 10/11 with strict deterministic CBOR and derived size
  limits (330 / 16,844,188 bytes);
- sign `[4, 10, claim_id, nonce]` with the fixed `SignMessage` semantics and
  self-verify immediately;
- verify stored Kind 8/9 evidence chains without reading any clock: both
  child signatures, Claim ID equality across Kind 10 / Kind 8 / Kind 9,
  payload count/order/hashes, and the Arbiter transaction signature over the
  rebuilt candidate;
- compare the embedded ClaimCBOR byte-for-byte against the locally rebuilt
  expected ClaimCBOR;
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
  Kind 9 before serving anything (`CustodyPrepared` records are NotReady);
- atomically occupy unique (ClaimID, Nonce) — database unique key,
  transaction/CAS, or equivalent — strictly after signature verification, so
  failed-signature requests never pollute the nonce table;
- protect requests and responses with TLS or an equivalently secure transport; the nonce does not substitute for confidentiality;
- define and publish retention policy; within retention a buyer may download
  repeatedly using fresh nonces, and the answer is Gone after retention ends with safe deletion;
- handle NotFound / NotReady / Unauthorized / NonceReused / Gone /
  RateLimited as transport/business errors, never as structurally valid
  Kind 11 responses;
- keep old nonce records at least as long as the corresponding custody record
  exists so an old signed request cannot become replayable again;
- log neither raw payloads, private keys, nor complete replayable requests;
  audit logs use Claim ID / nonce hashes and state only.

## Retry semantics

- The nonce is the replay key for one request, not a long-lived token.
- After a timeout or incomplete transfer the buyer generates a new nonce and
  a new Kind 10 signature — a new nonce for every retry; the arbiter never
  replays content for an old nonce.
- Concurrent identical (ClaimID, Nonce) requests resolve to exactly one
  winner by the unique key; every loser gets NonceReused.
- Expired quotes/deadlines/refunds do not reject already signed evidence;
  time gates were applied before Kind 9 was ever signed.
- If saving retrieved content fails, the batch is not marked complete; the
  buyer retries with a fresh nonce until its own atomic save succeeds.

## Acceptance checklist

- [ ] Only records whose exact Kind 8 + exact Kind 9 both persist are retrievable.
- [ ] The Claim ID routes the lookup; a mismatched Kind 10 Claim ID is invalid evidence, never a fuzzy search key.
- [ ] Every retrieval carries a valid Buyer signature under the key recovered from the stored Claim.
- [ ] A Claim ID alone authorizes nothing.
- [ ] The embedded Kind 8/9 are byte-identical to persisted bytes, never re-encoded.
- [ ] Payloads appear once; there is no second receipt copy.
- [ ] No 005, no close transaction, no broadcast side effect exists anywhere in this path.
