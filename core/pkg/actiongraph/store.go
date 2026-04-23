package actiongraph

import (
	"context"
	"fmt"
	"sync"
)

// ActionStore persists and retrieves ActionProposals.
type ActionStore interface {
	// Create stores a new proposal. Returns an error if the proposal ID
	// already exists.
	Create(ctx context.Context, proposal *ActionProposal) error

	// Get retrieves a proposal by ID. Returns an error if not found.
	Get(ctx context.Context, proposalID string) (*ActionProposal, error)

	// ListByStatus returns up to limit proposals matching the given status,
	// ordered by creation time (newest first).
	ListByStatus(ctx context.Context, status string, limit int) ([]*ActionProposal, error)

	// UpdateStatus transitions a proposal to a new status.
	UpdateStatus(ctx context.Context, proposalID, status string) error
}

// InMemoryActionStore is a thread-safe in-memory implementation of ActionStore,
// suitable for tests and development.
type InMemoryActionStore struct {
	mu        sync.RWMutex
	proposals map[string]*ActionProposal
}

// NewInMemoryActionStore returns a ready-to-use in-memory store.
func NewInMemoryActionStore() *InMemoryActionStore {
	return &InMemoryActionStore{
		proposals: make(map[string]*ActionProposal),
	}
}

// Create stores a new proposal.
func (s *InMemoryActionStore) Create(_ context.Context, proposal *ActionProposal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.proposals[proposal.ProposalID]; exists {
		return fmt.Errorf("actiongraph: proposal %q already exists", proposal.ProposalID)
	}
	s.proposals[proposal.ProposalID] = proposal
	return nil
}

// Get retrieves a proposal by ID.
func (s *InMemoryActionStore) Get(_ context.Context, proposalID string) (*ActionProposal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.proposals[proposalID]
	if !ok {
		return nil, fmt.Errorf("actiongraph: proposal %q not found", proposalID)
	}
	return p, nil
}

// ListByStatus returns up to limit proposals matching the given status.
func (s *InMemoryActionStore) ListByStatus(_ context.Context, status string, limit int) ([]*ActionProposal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*ActionProposal
	for _, p := range s.proposals {
		if p.Status == status {
			result = append(result, p)
			if len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

// UpdateStatus transitions a proposal to a new status.
func (s *InMemoryActionStore) UpdateStatus(_ context.Context, proposalID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.proposals[proposalID]
	if !ok {
		return fmt.Errorf("actiongraph: proposal %q not found", proposalID)
	}
	p.Status = status
	return nil
}
