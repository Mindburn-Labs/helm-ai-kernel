// Package intervention defines the public contracts for HELM's Human Intervention Fabric.
//
// The Intervention Fabric provides the canonical types and interfaces for
// human-in-the-loop governance: pausing execution, requiring human approval,
// capturing intervention decisions, and producing typed intervention receipts.
//
// Key types:
//   - InterventionObject: The request for human intervention
//   - InterventionReceipt: Cryptographic proof of human decision
//   - HandoffContract: Terms for delegating execution between principals
//
// Invariant: Every intervention MUST produce a signed receipt.
// The commercial HELM Platform extends this with escalation chains and
// multi-stakeholder approval workflows.
package intervention
