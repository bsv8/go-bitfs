# go-bitfs

go-bitfs is the source of truth for the BitFS v3 Go protocol: file exchange, arbitration, and MultisigPool v4 2-of-3 settlement. The implementation uses strict deterministic CBOR and preserves the exact signed bytes required for offline verification.

The protocol is documented in the multilingual [Docusaurus site](website/README.md). English is the normative website language; Simplified Chinese is maintained under `website/i18n/zh-CN/`.

| Step | Specification | Requirements and intent |
|---:|---|---|
| 001 | [Quote credential](website/docs/protocol/001-quote-credential-spec.md) | [Requirements](website/docs/protocol/001-quote-credential-requirements.md) |
| 002 | [Pool opening](website/docs/protocol/002-pool-opening-spec.md) | [Requirements](website/docs/protocol/002-pool-opening-requirements.md) |
| 003 | [Content request](website/docs/protocol/003-content-request-spec.md) | [Requirements](website/docs/protocol/003-content-request-requirements.md) |
| 004 | [Content delivery](website/docs/protocol/004-content-delivery-spec.md) | [Requirements](website/docs/protocol/004-content-delivery-requirements.md) |
| 005 | [Cumulative payment](website/docs/protocol/005-cumulative-payment-spec.md) | [Requirements](website/docs/protocol/005-cumulative-payment-requirements.md) |
| 006 | [Pool close](website/docs/protocol/006-unconditional-pool-close-spec.md) | [Requirements](website/docs/protocol/006-pool-close-requirements.md) |
| 007 | [Seller arbitration](website/docs/protocol/007-seller-arbitration-submission-spec.md) | [Requirements](website/docs/protocol/007-seller-arbitration-submission-requirements.md) |

The current CDDL is under `spec/v3/`. Transaction scripts, fees, signatures, and state construction are delegated to the published `github.com/bsv8/MultisigPool/v4` implementation. Network, queue, WebSocket, and database adapters remain application-owned interfaces.

## Packages

- `bitfs/`: quote and content credentials, seeds, hashes, and evidence validation.
- `pool/`: independent 002/005/006 settlement state machine, transaction engine, persistence ports, and memory reference implementation.
- `buyer/` and `seller/`: role workflows for the v3 protocol.
- `arbitration/` and `wire/`: arbitration evidence signing and typed protocol message dispatch.

Run the test suite with:

```bash
go test ./...
```
