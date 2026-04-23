package skills

import (
	"context"
	"fmt"
	"sync"
)

// SkillStore is the persistence interface for skills and proposals.
type SkillStore interface {
	// Skill CRUD
	CreateSkill(ctx context.Context, skill *Skill) error
	GetSkill(ctx context.Context, skillID string) (*Skill, error)
	ListSkills(ctx context.Context, level PromotionLevel) ([]*Skill, error)
	UpdateSkillLevel(ctx context.Context, skillID string, level PromotionLevel) error
	UpdateSkillStatus(ctx context.Context, skillID string, status string) error

	// Proposal CRUD
	CreateProposal(ctx context.Context, proposal *SkillProposal) error
	GetProposal(ctx context.Context, proposalID string) (*SkillProposal, error)
	ListPendingProposals(ctx context.Context) ([]*SkillProposal, error)

	// Promotion CRUD
	CreatePromotionRequest(ctx context.Context, req *PromotionRequest) error
	GetPromotionRequest(ctx context.Context, requestID string) (*PromotionRequest, error)
	UpdatePromotionStatus(ctx context.Context, requestID, status string) error

	// Lineage
	AppendLineage(ctx context.Context, entry *SkillLineageEntry) error
	GetLineage(ctx context.Context, skillID string) ([]*SkillLineageEntry, error)
}

// InMemorySkillStore implements SkillStore with in-memory maps.
type InMemorySkillStore struct {
	mu         sync.RWMutex
	skills     map[string]*Skill
	proposals  map[string]*SkillProposal
	promotions map[string]*PromotionRequest
	lineage    map[string][]*SkillLineageEntry // keyed by skillID
}

// NewInMemorySkillStore creates a new in-memory skill store.
func NewInMemorySkillStore() *InMemorySkillStore {
	return &InMemorySkillStore{
		skills:     make(map[string]*Skill),
		proposals:  make(map[string]*SkillProposal),
		promotions: make(map[string]*PromotionRequest),
		lineage:    make(map[string][]*SkillLineageEntry),
	}
}

func (s *InMemorySkillStore) CreateSkill(_ context.Context, skill *Skill) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.skills[skill.SkillID]; exists {
		return fmt.Errorf("skill %s already exists", skill.SkillID)
	}
	s.skills[skill.SkillID] = skill
	return nil
}

func (s *InMemorySkillStore) GetSkill(_ context.Context, skillID string) (*Skill, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	skill, ok := s.skills[skillID]
	if !ok {
		return nil, fmt.Errorf("skill %s not found", skillID)
	}
	return skill, nil
}

func (s *InMemorySkillStore) ListSkills(_ context.Context, level PromotionLevel) ([]*Skill, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Skill
	for _, skill := range s.skills {
		if skill.Level == level {
			result = append(result, skill)
		}
	}
	return result, nil
}

func (s *InMemorySkillStore) UpdateSkillLevel(_ context.Context, skillID string, level PromotionLevel) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	skill, ok := s.skills[skillID]
	if !ok {
		return fmt.Errorf("skill %s not found", skillID)
	}
	skill.Level = level
	return nil
}

func (s *InMemorySkillStore) UpdateSkillStatus(_ context.Context, skillID string, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	skill, ok := s.skills[skillID]
	if !ok {
		return fmt.Errorf("skill %s not found", skillID)
	}
	skill.Status = status
	return nil
}

func (s *InMemorySkillStore) CreateProposal(_ context.Context, proposal *SkillProposal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.proposals[proposal.ProposalID]; exists {
		return fmt.Errorf("proposal %s already exists", proposal.ProposalID)
	}
	s.proposals[proposal.ProposalID] = proposal
	return nil
}

func (s *InMemorySkillStore) GetProposal(_ context.Context, proposalID string) (*SkillProposal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	proposal, ok := s.proposals[proposalID]
	if !ok {
		return nil, fmt.Errorf("proposal %s not found", proposalID)
	}
	return proposal, nil
}

func (s *InMemorySkillStore) ListPendingProposals(_ context.Context) ([]*SkillProposal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*SkillProposal
	for _, p := range s.proposals {
		if p.Status == "PENDING" {
			result = append(result, p)
		}
	}
	return result, nil
}

func (s *InMemorySkillStore) CreatePromotionRequest(_ context.Context, req *PromotionRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.promotions[req.RequestID]; exists {
		return fmt.Errorf("promotion request %s already exists", req.RequestID)
	}
	s.promotions[req.RequestID] = req
	return nil
}

func (s *InMemorySkillStore) GetPromotionRequest(_ context.Context, requestID string) (*PromotionRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.promotions[requestID]
	if !ok {
		return nil, fmt.Errorf("promotion request %s not found", requestID)
	}
	return req, nil
}

func (s *InMemorySkillStore) UpdatePromotionStatus(_ context.Context, requestID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.promotions[requestID]
	if !ok {
		return fmt.Errorf("promotion request %s not found", requestID)
	}
	req.Status = status
	return nil
}

func (s *InMemorySkillStore) AppendLineage(_ context.Context, entry *SkillLineageEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lineage[entry.SkillID] = append(s.lineage[entry.SkillID], entry)
	return nil
}

func (s *InMemorySkillStore) GetLineage(_ context.Context, skillID string) ([]*SkillLineageEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries := s.lineage[skillID]
	// Return a copy to avoid data races
	result := make([]*SkillLineageEntry, len(entries))
	copy(result, entries)
	return result, nil
}
