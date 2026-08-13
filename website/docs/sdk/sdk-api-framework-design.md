---
id: sdk-api-framework-design
title: BitFS SDK API framework
---

# BitFS SDK API framework

This page is the public API blueprint, not a wire specification or directly compilable Go source. Implementations MUST follow protocol specifications 001–007; numbered specifications take precedence if this guide conflicts with them.

The framework is split by responsibility:

| Document | Purpose |
|---|---|
| [01 · Protocol foundations and CBOR](protocol-foundations-and-cbor.md) | Package boundaries, conventions, errors, unified `wire` encoding, and pure protocol functions. |
| [02 · External hooks and data types](external-hooks-and-data-types.md) | Signing, persistence, content, transaction engine, BSV node hooks, and key inputs. |
| [03 · Role workflow API](role-workflow-api.md) | Buyer, seller, and arbiter APIs and the shortest end-to-end call path. |
| [04 · Implementation roadmap](implementation-roadmap.md) | Implemented layers and required verification coverage. |

The SDK constructs, validates, and retains self-proving credentials. Applications provide transport, private-key custody, content storage, databases, and BSV nodes through interfaces. Database records support lookup, idempotency, and seller delivery protection; they never replace raw CBOR, raw transactions, or signatures.
