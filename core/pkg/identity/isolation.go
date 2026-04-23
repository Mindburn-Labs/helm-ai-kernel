package identity

import (
	"fmt"
	"sync"
	"time"
)

// IsolationChecker validates that agent instances maintain credential isolation.
// It detects when a different principal reuses a credential hash that was already
// bound to another principal — the primary attack vector for agent impersonation.
//
// Design invariants:
//   - First binding of (credentialHash → principal) is stored permanently
//   - Subsequent bindings of the same credentialHash to a different principal → violation
//   - Same principal re-binding the same credentialHash → allowed (idempotent)
//   - Thread-safe for concurrent agent operations
//   - All violations are receipted with timestamps
type IsolationChecker struct {
	mu       sync.RWMutex
	bindings map[string]string          // credentialHash → principalID
	history  []IsolationViolationRecord // all violations for audit
	clock    func() time.Time
}

// IsolationViolationRecord captures details of a credential reuse attempt.
type IsolationViolationRecord struct {
	CredentialHash      string    `json:"credential_hash"`
	AttemptingPrincipal string    `json:"attempting_principal"`
	BoundPrincipal      string    `json:"bound_principal"`
	SessionID           string    `json:"session_id"`
	DetectedAt          time.Time `json:"detected_at"`
}

// IsolationViolationError is returned when an agent reuses another agent's credentials.
type IsolationViolationError struct {
	CredentialHash      string `json:"credential_hash"`
	AttemptingPrincipal string `json:"attempting_principal"`
	BoundPrincipal      string `json:"bound_principal"`
}

func (e *IsolationViolationError) Error() string {
	return fmt.Sprintf("IDENTITY_ISOLATION_VIOLATION: credential bound to %s, attempted by %s",
		e.BoundPrincipal, e.AttemptingPrincipal)
}

// NewIsolationChecker creates a new IsolationChecker.
func NewIsolationChecker() *IsolationChecker {
	return &IsolationChecker{
		bindings: make(map[string]string),
		clock:    time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (ic *IsolationChecker) WithClock(clock func() time.Time) *IsolationChecker {
	ic.clock = clock
	return ic
}

// ValidateAgentIdentity checks whether the given principal is allowed to use
// the given credential hash. If the credential is already bound to a different
// principal, an IsolationViolationError is returned.
//
// Parameters:
//   - principalID: the agent's unique identifier
//   - credentialHash: SHA-256 hash of the credential being used
//   - sessionID: the current session identifier (for audit)
func (ic *IsolationChecker) ValidateAgentIdentity(principalID, credentialHash, sessionID string) error {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	if existing, ok := ic.bindings[credentialHash]; ok {
		if existing != principalID {
			violation := IsolationViolationRecord{
				CredentialHash:      credentialHash,
				AttemptingPrincipal: principalID,
				BoundPrincipal:      existing,
				SessionID:           sessionID,
				DetectedAt:          ic.clock(),
			}
			ic.history = append(ic.history, violation)

			return &IsolationViolationError{
				CredentialHash:      credentialHash,
				AttemptingPrincipal: principalID,
				BoundPrincipal:      existing,
			}
		}
		// Same principal, same credential — idempotent, allowed
		return nil
	}

	// First binding
	ic.bindings[credentialHash] = principalID
	return nil
}

// Violations returns all recorded isolation violations.
func (ic *IsolationChecker) Violations() []IsolationViolationRecord {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	out := make([]IsolationViolationRecord, len(ic.history))
	copy(out, ic.history)
	return out
}

// BindingCount returns the number of active credential bindings.
func (ic *IsolationChecker) BindingCount() int {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return len(ic.bindings)
}
