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
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
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

// WithCDMClock sets a custom clock function (primarily for testing).
func WithCDMClock(clock func() time.Time) CDMOption {
	return func(m *ContinuousDelegationManager) {
		m.clock = clock
	}
}

// ContinuousDelegationManager manages continuous delegations with TTL,
// refresh, revocation, and sub-delegation semantics.
// All methods are safe for concurrent use from multiple goroutines.
type ContinuousDelegationManager struct {
	mu          sync.RWMutex
	delegations map[string]*ContinuousDelegation // id -> delegation
	clock       func() time.Time
}

// NewContinuousDelegationManager creates a new manager with the given options.
func NewContinuousDelegationManager(opts ...CDMOption) *ContinuousDelegationManager {
	m := &ContinuousDelegationManager{
		delegations: make(map[string]*ContinuousDelegation),
		clock:       time.Now,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Grant creates a new continuous delegation from grantor to grantee with
// the specified scope and TTL. Returns the created delegation or an error
// if required fields are missing.
func (m *ContinuousDelegationManager) Grant(grantorID, granteeID string, scope []string, ttl time.Duration) (*ContinuousDelegation, error) {
	if grantorID == "" {
		return nil, fmt.Errorf("continuous_delegation: grantor ID is required")
	}
	if granteeID == "" {
		return nil, fmt.Errorf("continuous_delegation: grantee ID is required")
	}
	if len(scope) == 0 {
		return nil, fmt.Errorf("continuous_delegation: scope must contain at least one entry")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("continuous_delegation: TTL must be positive")
	}

	now := m.clock()
	d := &ContinuousDelegation{
		ID:          uuid.New().String(),
		GrantorID:   grantorID,
		GranteeID:   granteeID,
		Scope:       make([]string, len(scope)),
		TTL:         ttl,
		GrantedAt:   now,
		RefreshedAt: now,
	}
	copy(d.Scope, scope)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.delegations[d.ID] = d

	// Return a copy.
	cp := *d
	cp.Scope = make([]string, len(d.Scope))
	copy(cp.Scope, d.Scope)
	return &cp, nil
}

// Refresh extends a delegation's TTL by resetting the refresh timestamp.
// Returns an error if the delegation does not exist, is revoked, or has expired.
func (m *ContinuousDelegationManager) Refresh(delegationID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.delegations[delegationID]
	if !ok {
		return fmt.Errorf("continuous_delegation: delegation %q not found", delegationID)
	}
	if d.RevokedAt != nil {
		return fmt.Errorf("continuous_delegation: delegation %q is revoked", delegationID)
	}

	now := m.clock()
	if now.After(d.RefreshedAt.Add(d.TTL)) {
		return fmt.Errorf("continuous_delegation: delegation %q has expired", delegationID)
	}

	d.RefreshedAt = now
	return nil
}

// Revoke immediately revokes a delegation. Returns an error if the
// delegation does not exist.
func (m *ContinuousDelegationManager) Revoke(delegationID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.delegations[delegationID]
	if !ok {
		return fmt.Errorf("continuous_delegation: delegation %q not found", delegationID)
	}

	now := m.clock()
	d.RevokedAt = &now
	return nil
}

// IsActive checks whether a delegation is currently active: it exists,
// has not been revoked, and has not expired (time since last refresh < TTL).
func (m *ContinuousDelegationManager) IsActive(delegationID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	d, ok := m.delegations[delegationID]
	if !ok {
		return false
	}
	if d.RevokedAt != nil {
		return false
	}

	now := m.clock()
	return !now.After(d.RefreshedAt.Add(d.TTL))
}

// SubDelegate creates a sub-delegation from an existing delegation with
// narrowed scope. The sub-delegation's scope must be a subset of the
// parent's scope. The sub-delegation's TTL cannot exceed the parent's
// remaining lifetime. Returns an error on scope widening or invalid parent.
func (m *ContinuousDelegationManager) SubDelegate(parentID, newGranteeID string, narrowedScope []string) (*ContinuousDelegation, error) {
	if parentID == "" {
		return nil, fmt.Errorf("continuous_delegation: parent ID is required")
	}
	if newGranteeID == "" {
		return nil, fmt.Errorf("continuous_delegation: new grantee ID is required")
	}
	if len(narrowedScope) == 0 {
		return nil, fmt.Errorf("continuous_delegation: narrowed scope must contain at least one entry")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	parent, ok := m.delegations[parentID]
	if !ok {
		return nil, fmt.Errorf("continuous_delegation: parent delegation %q not found", parentID)
	}
	if parent.RevokedAt != nil {
		return nil, fmt.Errorf("continuous_delegation: parent delegation %q is revoked", parentID)
	}

	now := m.clock()
	if now.After(parent.RefreshedAt.Add(parent.TTL)) {
		return nil, fmt.Errorf("continuous_delegation: parent delegation %q has expired", parentID)
	}

	// Scope narrowing enforcement: all requested scopes must exist in parent.
	parentScopeSet := make(map[string]bool, len(parent.Scope))
	for _, s := range parent.Scope {
		parentScopeSet[s] = true
	}
	for _, s := range narrowedScope {
		if !parentScopeSet[s] {
			return nil, fmt.Errorf("continuous_delegation: scope widening rejected: %q not in parent scope", s)
		}
	}

	// Sub-delegation TTL is bounded by parent's remaining lifetime.
	remaining := parent.RefreshedAt.Add(parent.TTL).Sub(now)

	d := &ContinuousDelegation{
		ID:          uuid.New().String(),
		GrantorID:   parent.GranteeID,
		GranteeID:   newGranteeID,
		Scope:       make([]string, len(narrowedScope)),
		TTL:         remaining,
		GrantedAt:   now,
		RefreshedAt: now,
		ParentID:    parentID,
	}
	copy(d.Scope, narrowedScope)

	m.delegations[d.ID] = d

	// Return a copy.
	cp := *d
	cp.Scope = make([]string, len(d.Scope))
	copy(cp.Scope, d.Scope)
	return &cp, nil
}

// RevokeWithCascade revokes a delegation and all sub-delegations that
// chain from it (direct and transitive). Returns the total number of
// delegations revoked (including the root).
func (m *ContinuousDelegationManager) RevokeWithCascade(delegationID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock()
	count := 0

	// Use BFS to find all transitive sub-delegations.
	queue := []string{delegationID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		d, ok := m.delegations[current]
		if !ok {
			continue
		}
		if d.RevokedAt != nil {
			continue // Already revoked.
		}

		d.RevokedAt = &now
		count++

		// Find all children of this delegation.
		for _, child := range m.delegations {
			if child.ParentID == current && child.RevokedAt == nil {
				queue = append(queue, child.ID)
			}
		}
	}

	return count
}
