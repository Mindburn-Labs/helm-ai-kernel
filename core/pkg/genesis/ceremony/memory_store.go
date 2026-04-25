package ceremony

import (
	"fmt"
	"sync"
)

// MemoryStore is the default in-process store for genesis ceremonies.
// It is the OSS-default backing store; production deployments may
// substitute a durable Store (e.g. file-backed JSON or SQLite) without
// changing the Orchestrator API.
type MemoryStore struct {
	mu      sync.RWMutex
	byID    map[string]*Ceremony
	byOrgID map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byID:    map[string]*Ceremony{},
		byOrgID: map[string]string{},
	}
}

func (s *MemoryStore) Create(ceremony *Ceremony) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := cloneCeremony(ceremony)
	s.byID[ceremony.ID] = copy
	s.byOrgID[ceremony.OrgID] = ceremony.ID
	return nil
}

func (s *MemoryStore) Get(id string) (*Ceremony, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ceremony, ok := s.byID[id]
	if !ok {
		return nil, fmt.Errorf("genesis: ceremony %s not found", id)
	}
	return cloneCeremony(ceremony), nil
}

func (s *MemoryStore) Update(ceremony *Ceremony) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[ceremony.ID]; !ok {
		return fmt.Errorf("genesis: ceremony %s not found", ceremony.ID)
	}
	copy := cloneCeremony(ceremony)
	s.byID[ceremony.ID] = copy
	s.byOrgID[ceremony.OrgID] = ceremony.ID
	return nil
}

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

func cloneCeremony(ceremony *Ceremony) *Ceremony {
	copy := *ceremony
	if ceremony.Phases != nil {
		copy.Phases = make(map[Phase]*PhaseState, len(ceremony.Phases))
		for phase, state := range ceremony.Phases {
			stateCopy := *state
			copy.Phases[phase] = &stateCopy
		}
	}
	return &copy
}
