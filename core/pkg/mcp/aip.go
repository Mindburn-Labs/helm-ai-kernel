// aip.go implements the Agent Identity Protocol (AIP) for verifiable delegation
// verification in the MCP gateway.
// Per arXiv 2603.24775, no mechanism currently verifies an agent's authority
// to delegate tasks or constrains a delegate's scope in MCP.
//
// Design invariants:
//   - Delegation chains are verified before tool execution
//   - Scope narrowing enforced (delegate cannot exceed delegator's authority)
//   - Fail-closed: invalid delegation = blocked
//   - Thread-safe
package mcp

import (
	"sync"
	"time"
)

// DelegationClaim represents a signed assertion that one agent (delegator)
// grants another agent (delegate) authority over a defined scope.
type DelegationClaim struct {
	DelegatorID string    `json:"delegator_id"` // Who granted authority
	DelegateID  string    `json:"delegate_id"`  // Who received authority
	Scope       []string  `json:"scope"`        // Allowed tools/actions
	ExpiresAt   time.Time `json:"expires_at"`
	Signature   string    `json:"signature"` // Ed25519 sig from delegator
}

// AIPOption configures optional AIPVerifier settings.
type AIPOption func(*AIPVerifier)

// DelegationSignatureVerifier validates the cryptographic binding for a claim.
type DelegationSignatureVerifier func(DelegationClaim) error

// AIPVerifier verifies delegation chains for the Agent Identity Protocol.
// All methods are safe for concurrent use from multiple goroutines.
type AIPVerifier struct {
	mu              sync.RWMutex
	chains          map[string][]DelegationClaim // delegateID -> chain of claims
	clock           func() time.Time
	verifySignature DelegationSignatureVerifier
}
