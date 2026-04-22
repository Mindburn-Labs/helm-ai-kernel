// Package runtimeadapters provides the compatibility and interception layer
// for non-native agent runtimes (MCP, OpenClaw, generic HTTP tool callers).
//
// Every runtime adapter MUST:
//  1. Intercept all tool calls (non-bypassable)
//  2. Translate tool calls into HELM governance requests
//  3. Enforce the verdict (allow/deny/escalate)
//  4. Emit receipts and ProofGraph nodes
//  5. Expose deny reasons to the caller
//
// The RuntimeAdapter interface is the only public surface. Wrapped gateways
// are private fields to prevent governance bypass.
package runtimeadapters

import "context"

// RuntimeAdapter is the universal interface for runtime interception.
type RuntimeAdapter interface {
	// Intercept processes a tool call through HELM governance.
	// Returns the governed response or an error.
	Intercept(ctx context.Context, req *AdaptedRequest) (*AdaptedResponse, error)

	// ID returns the adapter identifier.
	ID() string
}
