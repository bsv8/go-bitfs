// Package buyer implements the stateless buyer-side protocol orchestrator
// for BitFS wire kinds 001–006 plus the 008 arbitrated content retrieval. A Workflow holds only the official BSV private key: it
// never loads or saves state, never reads or stores content, never broadcasts
// a transaction, and never queries a node or store; it reads system UTC exactly once at the start
// of each operation. Every business input (quote, opening proof, previous
// payment state, seed bytes, and block height) is passed explicitly by the
// calling application, and every
// method returns only computed wire messages, raw transactions, verified
// evidence, and local role state that the application must persist itself.
//
// This package is not a wallet, database client, node client, or concurrency
// coordinator. Applications own persistence, serialization, retries, routing,
// authorization, and recovery from failures.
//
// The Kind 7 payment credential produced by AcceptDelivery is minimal: the
// payment authorization ID (an application lookup key into the saved original
// signed Kind 5) plus the buyer payment transaction signature over the exact
// unsigned state transaction both sides rebuild locally. The wire never
// carries the pool correlation ID or the raw transaction; ID-bound does not
// mean ID-decodable.
//
// The 008 retrieval path is read-only content recovery: BuildArbitrationContentRequest
// rebuilds the Claim ID from the local opening plus the exact signed payment
// authorization and signs content_retrieval_request_cbor through the unified
// SignWireDocument(1, 10, ...) helper; AcceptArbitratedContent verifies the
// arbiter-signed Kind 11 result (request binding, signature, and payload ID
// binding) and returns payloads. An unavailable answer surfaces as
// arbitration.ErrContentUnavailable and changes no state.
// It never signs 005, never closes a pool, never broadcasts, and never reads
// storage. When the seller is unreachable and no custody record exists, the
// buyer waits for the seller or broadcasts its presigned RefundTemplateRaw after
// nLockTime; there is no buyer+arbiter close in this protocol.
package buyer
