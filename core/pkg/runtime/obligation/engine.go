package obligation

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ObligationStore defines the persistence interface.
type ObligationStore interface {
	Save(obligation *Obligation) error
	Get(id string) (*Obligation, error)
	FindPending() ([]*Obligation, error)
	// AtomicLease attempts to claim an obligation atomically for a given worker.
	AtomicLease(workerID string, duration time.Duration) (*Obligation, error)
}

// MemoryStore is an in-memory implementation of ObligationStore.
type MemoryStore struct {
	mu          sync.RWMutex
	obligations map[string]*Obligation
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		obligations: make(map[string]*Obligation),
	}
}

func (s *MemoryStore) Save(o *Obligation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.obligations[o.ID] = o
	return nil
}

func (s *MemoryStore) Get(id string) (*Obligation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if o, ok := s.obligations[id]; ok {
		return o, nil
	}
	return nil, errors.New("obligation not found")
}

func (s *MemoryStore) FindPending() ([]*Obligation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var pending []*Obligation
	for _, o := range s.obligations {
		if o.Status == StatusPending || (o.Status == StatusActive && time.Now().After(o.LeaseExpiry)) {
			pending = append(pending, o)
		}
	}
	return pending, nil
}

// AtomicLease attempts to claim an obligation atomically.
func (s *MemoryStore) AtomicLease(workerID string, duration time.Duration) (*Obligation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, o := range s.obligations {
		if o.Status == StatusPending || (o.Status == StatusActive && time.Now().After(o.LeaseExpiry)) {
			// Found candidate
			o.Status = StatusActive
			o.LeaseHolder = workerID
			o.LeaseExpiry = time.Now().Add(duration)
			o.UpdatedAt = time.Now()

			// Return a copy to avoid pointer races outside lock?
			// For MVP, returning pointer is acceptable if we respect ownership.
			return o, nil
		}
	}
	return nil, nil // None available
}

// ObligationEngine manages the lifecycle of obligations.
type ObligationEngine struct {
	store ObligationStore
}

func NewObligationEngine(store ObligationStore) *ObligationEngine {
	return &ObligationEngine{
		store: store,
	}
}

// CreateObligation initializes a new obligation.
func (e *ObligationEngine) CreateObligation(goalSpec string) (*Obligation, error) {
	o := &Obligation{
		ID:        uuid.New().String(),
		GoalSpec:  goalSpec,
		Status:    StatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Attempts:  []Attempt{},
	}
	if err := e.store.Save(o); err != nil {
		return nil, err
	}
	return o, nil
}

// Lease attempts to claim an obligation for a worker.
// Uses AtomicLease from the ObligationStore interface — no type assertions.
func (e *ObligationEngine) Lease(workerID string, duration time.Duration) (*Obligation, error) {
	o, err := e.store.AtomicLease(workerID, duration)
	if err != nil {
		return nil, err
	}
	if o == nil {
		return nil, nil
	}

	// Record attempt start
	attempt := Attempt{
		AttemptID: len(o.Attempts) + 1,
		WorkerID:  workerID,
		Status:    "IN_PROGRESS",
		StartedAt: time.Now(),
	}
	o.Attempts = append(o.Attempts, attempt)
	_ = e.store.Save(o) // Save attempt info

	return o, nil
}

// Complete marks an obligation as satisfied.
func (e *ObligationEngine) Complete(obligationID, receipt string) error {
	o, err := e.store.Get(obligationID)
	if err != nil {
		return err
	}

	o.Status = StatusSatisfied
	o.ResultReceipt = receipt
	o.UpdatedAt = time.Now()

	// Update last attempt
	if len(o.Attempts) > 0 {
		last := &o.Attempts[len(o.Attempts)-1]
		last.Status = "SUCCESS"
		last.EndedAt = time.Now()
	}

	return e.store.Save(o)
}

// Fail marks an obligation as failed or pending (for retry).
func (e *ObligationEngine) Fail(obligationID string, failureErr error) error {
	o, err := e.store.Get(obligationID)
	if err != nil {
		return err
	}

	// Update last attempt
	if len(o.Attempts) > 0 {
		last := &o.Attempts[len(o.Attempts)-1]
		last.Status = "FAILED"
		last.Error = failureErr.Error()
		last.EndedAt = time.Now()
	}

	// Escalation Logic (Gap 9)
	const MaxRetries = 3
	if len(o.Attempts) < MaxRetries {
		o.Status = StatusPending // Back to queue
		// Exponential backoff could be stored in o.LeaseExpiry here?
		// For now, immediate retry availability.
	} else {
		o.Status = StatusEscalated // Escalate!
		// Trigger notification/human loop here?
	}
	o.UpdatedAt = time.Now()

	return e.store.Save(o)
}
