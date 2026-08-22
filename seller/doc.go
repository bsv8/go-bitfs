// Package seller implements the stateless seller-side protocol orchestrator
// for BitFS v4 messages 001–007. A Workflow holds only the official BSV private key: it
// never loads or saves state, never reads or stores content, never holds a
// lease or lock, never broadcasts a transaction, and never queries a node or
// store; it reads system UTC exactly once at the start of each operation.
// Every business input (quote, opening proof, previous payment state,
// delivery context, content bytes, seed bytes, and block height) is passed
// explicitly by the calling application, and every method
// returns only computed wire messages, raw transactions, verified evidence,
// and local role state that the application must persist itself.
//
// Reading content from storage, persisting proofs and payments, sending wire
// messages, broadcasting transactions, retrying, and reconciling node results
// are all caller responsibilities.
package seller
