// Package seller implements the seller-side BitFS v3 workflow.
//
// A Workflow creates signed quotes, coordinates pool opening, validates content
// requests, delivers signed content, advances cumulative payments, and prepares
// arbitration evidence. Wallet, storage, content, transaction, and node
// capabilities remain application-owned and are supplied through WorkflowConfig.
package seller
