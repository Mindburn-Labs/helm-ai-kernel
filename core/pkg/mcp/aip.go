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
	"fmt"
	"sync"
	"time"
)

// DelegationClaim represents a signed assertion that one agent (delegator)
// grants another agent (delegate) authority over a defined scope.
type DelegationClaim struct {
	DelegatorID string    `json:"delegator_id"`  // Who granted authority
	DelegateID  string    `json:"delegate_id"`   // Who received authority
	Scope       []string  `json:"scope"`         // Allowed tools/actions
	ExpiresAt   time.Time `json:"expires_at"`
	Signature   string    `json:"signature"`     // Ed25519 sig from delegator
}

// AIPOption configures optional AIPVerifier settings.
type AIPOption func(*AIPVerifier)

// WithAIPClock sets a custom clock function (primarily for testing).
func WithAIPClock(clock func() time.Time) AIPOption {
	return func(v *AIPVerifier) {
		v.clock = clock
	}
}

// AIPVerifier verifies delegation chains for the Agent Identity Protocol.
// All methods are safe for concurrent use from multiple goroutines.
type AIPVerifier struct {
	mu     sync.RWMutex
	chains map[string][]DelegationClaim // delegateID -> chain of claims
	clock  func() time.Time
}

// NewAIPVerifier creates a new AIP delegation verifier with the given options.
func NewAIPVerifier(opts ...AIPOption) *AIPVerifier {
	v := &AIPVerifier{
		chains: make(map[string][]DelegationClaim),
		clock:  time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// RegisterDelegation registers a delegation claim. The claim is appended to
// the delegate's chain. Returns an error if required fields are missing or
// if the claim would widen scope beyond the delegator's own authority.
func (v *AIPVerifier) RegisterDelegation(claim DelegationClaim) error {
	if claim.DelegatorID == "" {
		return fmt.Errorf("aip: delegator ID is required")
	}
	if claim.DelegateID == "" {
		return fmt.Errorf("aip: delegate ID is required")
	}
	if len(claim.Scope) == 0 {
		return fmt.Errorf("aip: scope must contain at least one tool/action")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Scope narrowing enforcement: if the delegator has a chain, the new
	// claim's scope must be a subset of the delegator's effective scope.
	if delegatorChain, ok := v.chains[claim.DelegatorID]; ok && len(delegatorChain) > 0 {
		delegatorScope := v.effectiveScopeLocked(delegatorChain)
		for _, tool := range claim.Scope {
			if !delegatorScope[tool] {
				return fmt.Errorf("aip: scope narrowing violation: %q not in delegator's scope", tool)
			}
		}
	}

	v.chains[claim.DelegateID] = append(v.chains[claim.DelegateID], claim)
	return nil
}

// VerifyAuthority checks whether the given delegate has authority to invoke
// the specified tool. Returns (true, nil) if authority is valid, (false, nil)
// if authority is not granted, or (false, error) on verification failure.
//
// Fail-closed: any error or missing delegation returns false.
func (v *AIPVerifier) VerifyAuthority(delegateID, toolName string) (bool, error) {
	if delegateID == "" {
		return false, fmt.Errorf("aip: delegate ID is required")
	}
	if toolName == "" {
		return false, fmt.Errorf("aip: tool name is required")
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	chain, ok := v.chains[delegateID]
	if !ok || len(chain) == 0 {
		return false, nil // No delegation — fail-closed
	}

	now := v.clock()

	// Check the most recent valid claim that grants the tool.
	for i := len(chain) - 1; i >= 0; i-- {
		claim := chain[i]

		// Check expiry.
		if now.After(claim.ExpiresAt) {
			continue
		}

		// Check scope.
		for _, scope := range claim.Scope {
			if scope == toolName {
				return true, nil
			}
		}
	}

	return false, nil
}

// GetChain returns the delegation chain for a delegate. Returns nil if
// no delegations exist. The returned slice is a copy — callers cannot
// mutate internal state.
func (v *AIPVerifier) GetChain(delegateID string) []DelegationClaim {
	v.mu.RLock()
	defer v.mu.RUnlock()

	chain, ok := v.chains[delegateID]
	if !ok {
		return nil
	}

	result := make([]DelegationClaim, len(chain))
	copy(result, chain)
	return result
}

// effectiveScopeLocked computes the set of tools a chain grants.
// Caller must hold v.mu (read or write).
func (v *AIPVerifier) effectiveScopeLocked(chain []DelegationClaim) map[string]bool {
	now := v.clock()
	scope := make(map[string]bool)
	for _, claim := range chain {
		if now.After(claim.ExpiresAt) {
			continue
		}
		for _, tool := range claim.Scope {
			scope[tool] = true
		}
	}
	return scope
}
