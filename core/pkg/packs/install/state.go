package install

import (
	"fmt"
	"sync"
	"time"
)

// State captures the installed state of a single pack for the local
// operator. It is intentionally tenant-free: commercial callers that
// need per-tenant scoping wrap the Store, keyed by their own tenant ID.
type State struct {
	PackID       string     `json:"pack_id"`
	Version      string     `json:"version"`
	Status       string     `json:"status"`
	InstalledBy  string     `json:"installed_by,omitempty"`
	ReceiptID    string     `json:"receipt_id,omitempty"`
	ReceiptHash  string     `json:"receipt_hash,omitempty"`
	ManifestHash string     `json:"manifest_hash,omitempty"`
	LastAction   string     `json:"last_action,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
	InstallCount int        `json:"install_count,omitempty"`
	VerifiedAt   *time.Time `json:"verified_at,omitempty"`
	InstalledAt  *time.Time `json:"installed_at,omitempty"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Store persists the install state of packs. It is the minimal
// persistence surface needed by the install runtime.
//
// ErrStateNotFound MUST be returned when a pack has no recorded state.
// Callers distinguish "never installed" from "lookup failed" via this
// sentinel.
type Store interface {
	Get(packID string) (*State, error)
	Put(state *State) error
	Delete(packID string) error
	List() ([]*State, error)
}

// ErrStateNotFound signals a pack has no recorded state.
var ErrStateNotFound = fmt.Errorf("packs/install: state not found")

// MemoryStore is the default in-process Store for single-operator OSS
// deployments. Concurrent-safe via a single mutex.
type MemoryStore struct {
	mu     sync.RWMutex
	states map[string]*State
}

// NewMemoryStore returns a new empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{states: map[string]*State{}}
}

// Get returns the state for a pack, or ErrStateNotFound if the pack has
// no recorded state. The returned pointer is a clone; mutations by the
// caller do not leak into the store.
func (s *MemoryStore) Get(packID string) (*State, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.states[packID]
	if !ok {
		return nil, ErrStateNotFound
	}
	return cloneState(state), nil
}

// Put stores the state. The stored value is a clone; mutations by the
// caller after Put do not leak into the store.
func (s *MemoryStore) Put(state *State) error {
	if state == nil {
		return fmt.Errorf("packs/install: Put called with nil state")
	}
	if state.PackID == "" {
		return fmt.Errorf("packs/install: state.PackID required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.PackID] = cloneState(state)
	return nil
}

// Delete removes a pack's state. Returns ErrStateNotFound if absent.
func (s *MemoryStore) Delete(packID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.states[packID]; !ok {
		return ErrStateNotFound
	}
	delete(s.states, packID)
	return nil
}

// List returns a snapshot of all recorded states, ordered by PackID for
// deterministic iteration.
func (s *MemoryStore) List() ([]*State, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*State, 0, len(s.states))
	for _, state := range s.states {
		out = append(out, cloneState(state))
	}
	sortStatesByPackID(out)
	return out, nil
}

func cloneState(state *State) *State {
	if state == nil {
		return nil
	}
	copy := *state
	if state.VerifiedAt != nil {
		t := *state.VerifiedAt
		copy.VerifiedAt = &t
	}
	if state.InstalledAt != nil {
		t := *state.InstalledAt
		copy.InstalledAt = &t
	}
	return &copy
}

// sortStatesByPackID sorts in place by PackID ascending. Insertion sort
// is fine here — N is small (installed packs on a single operator).
func sortStatesByPackID(states []*State) {
	for i := 1; i < len(states); i++ {
		for j := i; j > 0 && states[j-1].PackID > states[j].PackID; j-- {
			states[j-1], states[j] = states[j], states[j-1]
		}
	}
}
