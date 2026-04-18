package ceremony

import (
	"fmt"
	"sync"
)

// MemoryStore is the default in-process Store implementation for ceremonies.
// All reads and writes deep-clone the stored Ceremony so callers cannot mutate
// persistent state through returned pointers.
type MemoryStore struct {
	mu      sync.RWMutex
	byID    map[string]*Ceremony
	byOrgID map[string]string
}

// NewMemoryStore constructs an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byID:    map[string]*Ceremony{},
		byOrgID: map[string]string{},
	}
}

// Create persists a new ceremony. The stored copy is independent of the input.
func (s *MemoryStore) Create(ceremony *Ceremony) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := cloneCeremony(ceremony)
	s.byID[ceremony.ID] = stored
	s.byOrgID[ceremony.OrgID] = ceremony.ID
	return nil
}

// Get returns a deep-cloned copy of the ceremony with the given id.
func (s *MemoryStore) Get(id string) (*Ceremony, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ceremony, ok := s.byID[id]
	if !ok {
		return nil, fmt.Errorf("genesis: ceremony %s not found", id)
	}
	return cloneCeremony(ceremony), nil
}

// Update replaces an existing ceremony with a deep-cloned copy of the input.
func (s *MemoryStore) Update(ceremony *Ceremony) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[ceremony.ID]; !ok {
		return fmt.Errorf("genesis: ceremony %s not found", ceremony.ID)
	}
	stored := cloneCeremony(ceremony)
	s.byID[ceremony.ID] = stored
	s.byOrgID[ceremony.OrgID] = ceremony.ID
	return nil
}

// GetByOrg returns a deep-cloned copy of the ceremony for the given org.
func (s *MemoryStore) GetByOrg(orgID string) (*Ceremony, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byOrgID[orgID]
	if !ok {
		return nil, fmt.Errorf("genesis: ceremony for org %s not found", orgID)
	}
	ceremony, ok := s.byID[id]
	if !ok {
		return nil, fmt.Errorf("genesis: ceremony %s not found", id)
	}
	return cloneCeremony(ceremony), nil
}

// cloneCeremony returns a deep-copy of ceremony (Phases map and its values).
func cloneCeremony(ceremony *Ceremony) *Ceremony {
	dup := *ceremony
	if ceremony.Phases != nil {
		dup.Phases = make(map[Phase]*PhaseState, len(ceremony.Phases))
		for phase, state := range ceremony.Phases {
			stateCopy := *state
			dup.Phases[phase] = &stateCopy
		}
	}
	return &dup
}
