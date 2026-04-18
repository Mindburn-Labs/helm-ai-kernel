package install

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// State is the persistent install state for a single pack (scoped to a
// logical installation; no tenant identifier is carried in OSS).
type State struct {
	PackID          string     `json:"pack_id"`
	Version         string     `json:"version"`
	Status          string     `json:"status"`
	ManifestHash    string     `json:"manifest_hash"`
	PrevReceiptHash string     `json:"prev_receipt_hash,omitempty"`
	LastAction      string     `json:"last_action"`
	LastError       string     `json:"last_error,omitempty"`
	InstallCount    int        `json:"install_count"`
	InstalledAt     *time.Time `json:"installed_at,omitempty"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// Store is the persistence interface for install state.
type Store interface {
	Get(packID string) (*State, error)
	Put(state *State) error
	Delete(packID string) error
	List() ([]*State, error)
}

// ErrInvalidState is returned by Store.Put when the provided state is
// structurally invalid (e.g. empty PackID).
var ErrInvalidState = errors.New("install: invalid state")

// MemoryStore is the default in-process Store. Reads deep-clone so callers
// cannot mutate persistent state through returned pointers.
type MemoryStore struct {
	mu   sync.RWMutex
	byID map[string]*State
}

// NewMemoryStore constructs an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{byID: map[string]*State{}}
}

// Get returns a deep-cloned copy of the state for packID.
func (s *MemoryStore) Get(packID string) (*State, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.byID[packID]
	if !ok {
		return nil, fmt.Errorf("install: state for pack %s not found", packID)
	}
	return cloneState(state), nil
}

// Put persists a deep-cloned copy of state. Returns ErrInvalidState if the
// state is missing its PackID.
func (s *MemoryStore) Put(state *State) error {
	if state == nil || state.PackID == "" {
		return ErrInvalidState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[state.PackID] = cloneState(state)
	return nil
}

// Delete removes any persisted state for packID.
func (s *MemoryStore) Delete(packID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, packID)
	return nil
}

// List returns deep-cloned copies of all persisted states.
func (s *MemoryStore) List() ([]*State, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*State, 0, len(s.byID))
	for _, state := range s.byID {
		out = append(out, cloneState(state))
	}
	return out, nil
}

func cloneState(state *State) *State {
	if state == nil {
		return nil
	}
	dup := *state
	if state.InstalledAt != nil {
		t := *state.InstalledAt
		dup.InstalledAt = &t
	}
	return &dup
}
