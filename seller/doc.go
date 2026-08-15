// Package seller implements the seller-side BitFS v3 workflow.
//
// A Workflow creates signed quotes, coordinates pool opening, validates content
// requests, delivers signed content, advances cumulative payments, and prepares
// arbitration evidence. Wallet, storage, content, and raw BSV backend
// capabilities remain application-owned and are supplied through WorkflowConfig.
// A seller typically creates a 001 quote, completes 002, serves validated 003
// requests with 004 deliveries, accepts 005 payments, and builds 007 evidence
// only when the buyer-authorized state requires arbitration.
package seller
