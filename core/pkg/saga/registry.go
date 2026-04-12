package saga

import (
	"fmt"
	"sync"
	"time"
)

// ActionRegistration describes a reversible action and its compensation.
type ActionRegistration struct {
	ActionID       string        `json:"action_id"`
	Reversible     bool          `json:"reversible"`
	CompensatingID string        `json:"compensating_id"` // action name for compensation
	MaxRetries     int           `json:"max_retries"`
	Timeout        time.Duration `json:"timeout"`
}

// ReversibilityRegistry tracks which actions are reversible and their compensating actions.
type ReversibilityRegistry struct {
	mu      sync.RWMutex
	actions map[string]ActionRegistration
}

// NewReversibilityRegistry creates a new registry.
func NewReversibilityRegistry() *ReversibilityRegistry {
	return &ReversibilityRegistry{
		actions: make(map[string]ActionRegistration),
	}
}

// Register adds an action registration. Returns an error if the action ID is empty.
func (r *ReversibilityRegistry) Register(reg ActionRegistration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if reg.ActionID == "" {
		return fmt.Errorf("action ID is required")
	}
	r.actions[reg.ActionID] = reg
	return nil
}

// Lookup returns the registration for an action.
func (r *ReversibilityRegistry) Lookup(actionID string) (ActionRegistration, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.actions[actionID]
	return reg, ok
}

// IsReversible returns whether an action can be compensated.
func (r *ReversibilityRegistry) IsReversible(actionID string) bool {
	reg, ok := r.Lookup(actionID)
	return ok && reg.Reversible
}

// ListActions returns all registered action IDs.
func (r *ReversibilityRegistry) ListActions() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.actions))
	for id := range r.actions {
		ids = append(ids, id)
	}
	return ids
}
