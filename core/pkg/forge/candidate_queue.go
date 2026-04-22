// Package forge implements the Forge mutation authority (ADR-004).
// The Forge is the ONLY valid path for evaluating, canary-testing, and
// promoting skill candidates — fail-closed by design.
package forge

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CandidateStatus represents the lifecycle state of a skill candidate.
type CandidateStatus string

const (
	// CandidateQueued is the initial state after submission.
	CandidateQueued CandidateStatus = "queued"
	// CandidateEvaluating means evaluation checks are running.
	CandidateEvaluating CandidateStatus = "evaluating"
	// CandidateReady means evaluation passed and the candidate awaits promotion.
	CandidateReady CandidateStatus = "ready"
	// CandidatePromoted means the candidate was successfully promoted.
	CandidatePromoted CandidateStatus = "promoted"
	// CandidateRejected means the candidate failed evaluation or was denied.
	CandidateRejected CandidateStatus = "rejected"
)

// Candidate is a skill version submitted for Forge evaluation.
type Candidate struct {
	CandidateID     string          `json:"candidate_id"`
	SkillID         string          `json:"skill_id"`
	TenantID        string          `json:"tenant_id"`
	SourceRef       string          `json:"source_ref"`              // what triggered this candidate
	SelfModClass    string          `json:"self_mod_class"`          // C0, C1, C2, C3
	Status          CandidateStatus `json:"status"`
	EvalProfileRef  string          `json:"eval_profile_ref"`
	EvalVerdict     string          `json:"eval_verdict,omitempty"`
	EvalEvidenceRef string          `json:"eval_evidence_ref,omitempty"`
	QueuedAt        time.Time       `json:"queued_at"`
	EvaluatedAt     *time.Time      `json:"evaluated_at,omitempty"`
	DecidedAt       *time.Time      `json:"decided_at,omitempty"`
}

// CandidateQueue manages the ordered list of skill candidates awaiting evaluation.
// Implementations must be safe for concurrent use.
type CandidateQueue interface {
	// Enqueue adds a candidate to the queue. Returns an error if a candidate
	// with the same CandidateID already exists.
	Enqueue(ctx context.Context, candidate Candidate) error
	// Dequeue returns and removes the oldest queued candidate, or nil if empty.
	Dequeue(ctx context.Context) (*Candidate, error)
	// Get returns the candidate with the given ID, or an error if not found.
	Get(ctx context.Context, candidateID string) (*Candidate, error)
	// List returns all candidates belonging to a tenant, in queue order.
	List(ctx context.Context, tenantID string) ([]Candidate, error)
	// UpdateStatus transitions a candidate to a new status.
	// Returns an error if the candidate does not exist.
	UpdateStatus(ctx context.Context, candidateID string, status CandidateStatus) error
}

// InMemoryCandidateQueue is a thread-safe, in-memory implementation of CandidateQueue.
// Suitable for testing and single-node deployments; not durable across restarts.
type InMemoryCandidateQueue struct {
	mu         sync.RWMutex
	candidates map[string]*Candidate // keyed by CandidateID
	order      []string              // insertion order for FIFO Dequeue
}

// NewInMemoryCandidateQueue returns a ready-to-use InMemoryCandidateQueue.
func NewInMemoryCandidateQueue() *InMemoryCandidateQueue {
	return &InMemoryCandidateQueue{
		candidates: make(map[string]*Candidate),
	}
}

// Enqueue adds a candidate. Returns an error if CandidateID is empty or already present.
func (q *InMemoryCandidateQueue) Enqueue(_ context.Context, candidate Candidate) error {
	if candidate.CandidateID == "" {
		return fmt.Errorf("forge: candidate CandidateID must not be empty")
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if _, exists := q.candidates[candidate.CandidateID]; exists {
		return fmt.Errorf("forge: candidate %q already exists", candidate.CandidateID)
	}

	if candidate.Status == "" {
		candidate.Status = CandidateQueued
	}
	if candidate.QueuedAt.IsZero() {
		candidate.QueuedAt = time.Now()
	}

	cp := candidate
	q.candidates[candidate.CandidateID] = &cp
	q.order = append(q.order, candidate.CandidateID)

	return nil
}

// Dequeue returns the next candidate whose status is CandidateQueued and
// removes it from the FIFO head. Returns nil when no queued candidate exists.
func (q *InMemoryCandidateQueue) Dequeue(_ context.Context) (*Candidate, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for i, id := range q.order {
		c, ok := q.candidates[id]
		if !ok {
			continue
		}
		if c.Status == CandidateQueued {
			// Remove from order slice.
			q.order = append(q.order[:i], q.order[i+1:]...)
			// Remove from map — caller owns the returned value.
			delete(q.candidates, id)
			cp := *c
			return &cp, nil
		}
	}

	return nil, nil //nolint:nilnil // intentional: empty queue is not an error
}

// Get returns a copy of the candidate with the given ID.
func (q *InMemoryCandidateQueue) Get(_ context.Context, candidateID string) (*Candidate, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	c, ok := q.candidates[candidateID]
	if !ok {
		return nil, fmt.Errorf("forge: candidate %q not found", candidateID)
	}

	cp := *c
	return &cp, nil
}

// List returns all candidates for a tenant in insertion order.
func (q *InMemoryCandidateQueue) List(_ context.Context, tenantID string) ([]Candidate, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var result []Candidate
	for _, id := range q.order {
		c, ok := q.candidates[id]
		if !ok {
			continue
		}
		if c.TenantID == tenantID {
			result = append(result, *c)
		}
	}

	return result, nil
}

// UpdateStatus changes the status of an existing candidate.
func (q *InMemoryCandidateQueue) UpdateStatus(_ context.Context, candidateID string, status CandidateStatus) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	c, ok := q.candidates[candidateID]
	if !ok {
		return fmt.Errorf("forge: candidate %q not found", candidateID)
	}

	c.Status = status
	return nil
}
