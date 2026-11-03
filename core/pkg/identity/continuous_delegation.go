// continuous_delegation.go implements AITH-style continuous delegation
// for human-AI trust establishment.
// Per arXiv 2604.07695, delegation is continuous (not one-shot), time-bound,
// revocable, and scope-narrowing.
//
// Design invariants:
//   - Delegations have TTL and must be refreshed
//   - Scope can only narrow, never widen
//   - Revocation is immediate and propagates to sub-delegates
//   - Thread-safe
package identity

import (
	"sync"
	"time"
)

// ContinuousDelegation represents a time-bound, refreshable delegation
// that must be actively maintained. Unlike one-shot delegation, these
// expire unless refreshed within their TTL window.
type ContinuousDelegation struct {
	ID          string        `json:"id"`
	GrantorID   string        `json:"grantor_id"`
	GranteeID   string        `json:"grantee_id"`
	Scope       []string      `json:"scope"`
	TTL         time.Duration `json:"ttl"`
	GrantedAt   time.Time     `json:"granted_at"`
	RefreshedAt time.Time     `json:"refreshed_at"`
	RevokedAt   *time.Time    `json:"revoked_at,omitempty"`
	ParentID    string        `json:"parent_id,omitempty"` // For sub-delegation chains
}

// CDMOption configures optional ContinuousDelegationManager settings.
type CDMOption func(*ContinuousDelegationManager)

// ContinuousDelegationManager manages continuous delegations with TTL,
// refresh, revocation, and sub-delegation semantics.
// All methods are safe for concurrent use from multiple goroutines.
type ContinuousDelegationManager struct {
	mu          sync.RWMutex
	delegations map[string]*ContinuousDelegation // id -> delegation
	clock       func() time.Time
}
