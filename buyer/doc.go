// Package buyer implements the buyer-side BitFS v3 workflow.
//
// A Workflow verifies and stores seller quotes, coordinates pool opening,
// creates signed content requests, verifies deliveries, and produces cumulative
// payment updates. Wallet, storage, content, transaction, and node capabilities
// remain application-owned and are supplied through WorkflowConfig.
package buyer
