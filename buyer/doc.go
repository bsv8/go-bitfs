// Package buyer implements the stateless buyer-side protocol orchestrator
// for BitFS v4 messages 001–006 plus the 008 arbitrated content retrieval. A Workflow holds only the official BSV private key: it
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
// The 005 payment credential produced by AcceptDelivery is minimal: the
// payment authorization hash (an application lookup key into the saved
// original signed 003) plus the buyer transaction signature over the exact
// unsigned state transaction both sides rebuild locally. The wire never
// carries the pool correlation ID or the raw transaction; hash-bound does not
// mean hash-decodable.
//
// The 008 retrieval path is read-only content recovery: BuildArbitrationContentRequest
// rebuilds the Claim ID from the local opening plus the exact signed 003 and signs
// [4,10,claim_id,nonce]; AcceptArbitratedContent verifies the returned exact
// Kind 8/9 evidence pair byte for byte and returns payloads plus audit data.
// It never signs 005, never closes a pool, never broadcasts, and never reads
// storage. When the seller is unreachable and no custody record exists, the
// buyer waits for the seller or broadcasts its presigned RefundTx after
// nLockTime; there is no buyer+arbiter close in this protocol.
package buyer
