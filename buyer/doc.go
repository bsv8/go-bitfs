// Package buyer implements the stateless buyer-side protocol orchestrator
// for BitFS v4 messages 001–006. A Workflow holds only the official BSV private key: it
// never loads or saves state, never reads or stores content, never broadcasts
// a transaction, and never queries a node or store; it reads system UTC exactly once at the start
// of each operation. Every business input (quote, opening proof, previous
// payment state, seed bytes, and block height) is passed explicitly by the
// calling application, and every
// method returns only computed wire messages, raw transactions, verified
// evidence, and local role state that the application must persist itself.
//
// This package is not a wallet, database client, node client, or concurrency
// coordinator. Applications own persistence, serialization, retries, routing
// by RefundTemplateTxID, authorization, and recovery from failures.
package buyer
