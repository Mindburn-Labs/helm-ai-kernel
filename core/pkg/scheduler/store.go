package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Sentinel errors returned by ScheduleStore implementations.
var (
	ErrScheduleNotFound    = errors.New("schedule not found")
	ErrScheduleExists      = errors.New("schedule already exists")
	ErrIdempotencyKeyFound = errors.New("idempotency key already dispatched")
)

// ScheduleStore is the persistence interface required by DefaultScheduler.
// Implementations must be safe for concurrent use.
type ScheduleStore interface {
	// Put upserts a ScheduleSpec. Creates or replaces.
	Put(ctx context.Context, spec ScheduleSpec) error

	// Get retrieves a ScheduleSpec by ID. Returns ErrScheduleNotFound when absent.
	Get(ctx context.Context, scheduleID string) (*ScheduleSpec, error)

	// List returns all schedules for a tenant (may be empty).
	List(ctx context.Context, tenantID string) ([]ScheduleSpec, error)

	// ListEnabled returns all enabled schedules across all tenants.
	ListEnabled(ctx context.Context) ([]ScheduleSpec, error)

	// Delete removes a schedule. Returns ErrScheduleNotFound when absent.
	Delete(ctx context.Context, scheduleID string) error

	// RecordDispatch persists a dispatch event for deduplication and audit.
	RecordDispatch(ctx context.Context, scheduleID string, firedAt time.Time, idempotencyKey string) error

	// WasDispatched reports whether an idempotency key has already been dispatched.
	WasDispatched(ctx context.Context, idempotencyKey string) (bool, error)
}

// dispatchRecord is the internal record kept by InMemoryScheduleStore.
type dispatchRecord struct {
	ScheduleID     string
	FiredAt        time.Time
	IdempotencyKey string
}

// InMemoryScheduleStore is a thread-safe, non-persistent ScheduleStore.
// It is intended for tests and in-process use; data is lost on process exit.
type InMemoryScheduleStore struct {
	mu        sync.RWMutex
	schedules map[string]ScheduleSpec      // scheduleID → spec
	dispatched map[string]dispatchRecord   // idempotencyKey → record
}

// NewInMemoryScheduleStore returns an initialised, empty InMemoryScheduleStore.
func NewInMemoryScheduleStore() *InMemoryScheduleStore {
	return &InMemoryScheduleStore{
		schedules:  make(map[string]ScheduleSpec),
		dispatched: make(map[string]dispatchRecord),
	}
}

// Put upserts a ScheduleSpec.
func (s *InMemoryScheduleStore) Put(_ context.Context, spec ScheduleSpec) error {
	if spec.ScheduleID == "" {
		return fmt.Errorf("store.Put: %w", ErrEmptyScheduleID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.schedules[spec.ScheduleID] = spec
	return nil
}

// Get retrieves a ScheduleSpec by ID.
func (s *InMemoryScheduleStore) Get(_ context.Context, scheduleID string) (*ScheduleSpec, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	spec, ok := s.schedules[scheduleID]
	if !ok {
		return nil, fmt.Errorf("store.Get %q: %w", scheduleID, ErrScheduleNotFound)
	}
	copy := spec
	return &copy, nil
}

// List returns all schedules for the given tenantID.
func (s *InMemoryScheduleStore) List(_ context.Context, tenantID string) ([]ScheduleSpec, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []ScheduleSpec
	for _, spec := range s.schedules {
		if spec.TenantID == tenantID {
			result = append(result, spec)
		}
	}
	return result, nil
}

// ListEnabled returns all enabled schedules across all tenants.
func (s *InMemoryScheduleStore) ListEnabled(_ context.Context) ([]ScheduleSpec, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []ScheduleSpec
	for _, spec := range s.schedules {
		if spec.Enabled {
			result = append(result, spec)
		}
	}
	return result, nil
}

// Delete removes a schedule by ID.
func (s *InMemoryScheduleStore) Delete(_ context.Context, scheduleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.schedules[scheduleID]; !ok {
		return fmt.Errorf("store.Delete %q: %w", scheduleID, ErrScheduleNotFound)
	}
	delete(s.schedules, scheduleID)
	return nil
}

// RecordDispatch records an idempotency key as dispatched.
func (s *InMemoryScheduleStore) RecordDispatch(_ context.Context, scheduleID string, firedAt time.Time, idempotencyKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dispatched[idempotencyKey] = dispatchRecord{
		ScheduleID:     scheduleID,
		FiredAt:        firedAt,
		IdempotencyKey: idempotencyKey,
	}
	return nil
}

// WasDispatched reports whether the idempotency key has already been dispatched.
func (s *InMemoryScheduleStore) WasDispatched(_ context.Context, idempotencyKey string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.dispatched[idempotencyKey]
	return ok, nil
}
