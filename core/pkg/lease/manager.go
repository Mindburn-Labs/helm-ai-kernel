package lease

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// LeaseManager manages the lifecycle of execution leases.
type LeaseManager interface {
	// Acquire creates a new lease in PENDING status.
	Acquire(ctx context.Context, req LeaseRequest) (*ExecutionLease, error)

	// Activate transitions a PENDING lease to ACTIVE.
	Activate(ctx context.Context, leaseID string, sandboxID string) error

	// Complete marks an ACTIVE lease as COMPLETED.
	Complete(ctx context.Context, leaseID string) error

	// Extend extends the TTL of an ACTIVE lease.
	Extend(ctx context.Context, leaseID string, duration time.Duration) error

	// Revoke terminates a lease with a reason.
	Revoke(ctx context.Context, leaseID string, reason string) error

	// Get returns a lease by ID. Returns nil if not found.
	Get(ctx context.Context, leaseID string) (*ExecutionLease, error)

	// ListActive returns all non-terminal leases.
	ListActive(ctx context.Context) ([]*ExecutionLease, error)

	// ExpireStale transitions any ACTIVE lease past its ExpiresAt to EXPIRED.
	ExpireStale(ctx context.Context) (int, error)
}

// InMemoryLeaseManager is a thread-safe in-memory implementation.
type InMemoryLeaseManager struct {
	mu      sync.Mutex
	leases  map[string]*ExecutionLease
	clock   func() time.Time
	counter int64
}

// NewInMemoryLeaseManager creates a new in-memory lease manager.
func NewInMemoryLeaseManager() *InMemoryLeaseManager {
	return &InMemoryLeaseManager{
		leases: make(map[string]*ExecutionLease),
		clock:  time.Now,
	}
}

// WithClock overrides the clock for testing.
func (m *InMemoryLeaseManager) WithClock(clock func() time.Time) *InMemoryLeaseManager {
	m.clock = clock
	return m
}

// Acquire creates a new lease in PENDING status.
func (m *InMemoryLeaseManager) Acquire(_ context.Context, req LeaseRequest) (*ExecutionLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if req.RunID == "" {
		return nil, fmt.Errorf("run_id is required")
	}
	if req.Backend == "" {
		return nil, fmt.Errorf("backend is required")
	}
	if req.TTL <= 0 {
		return nil, fmt.Errorf("TTL must be positive")
	}

	now := m.clock()
	m.counter++

	lease := &ExecutionLease{
		LeaseID:         fmt.Sprintf("lease-%d", m.counter),
		RunID:           req.RunID,
		WorkspacePath:   req.WorkspacePath,
		Backend:         req.Backend,
		ProfileName:     req.ProfileName,
		TemplateRef:     req.TemplateRef,
		TTL:             req.TTL,
		Status:          LeaseStatusPending,
		EffectGraphHash: req.EffectGraphHash,
		SecretBindings:  req.SecretBindings,
		CreatedAt:       now,
		ExpiresAt:       now.Add(req.TTL),
	}

	m.leases[lease.LeaseID] = lease

	// Return a copy.
	copy := *lease
	return &copy, nil
}

// Activate transitions PENDING → ACTIVE.
func (m *InMemoryLeaseManager) Activate(_ context.Context, leaseID string, sandboxID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	lease, ok := m.leases[leaseID]
	if !ok {
		return fmt.Errorf("lease not found: %s", leaseID)
	}
	if lease.Status != LeaseStatusPending {
		return fmt.Errorf("cannot activate lease in %s state", lease.Status)
	}

	lease.Status = LeaseStatusActive
	lease.SandboxID = sandboxID
	lease.ActivatedAt = m.clock()
	return nil
}

// Complete marks an ACTIVE lease as COMPLETED.
func (m *InMemoryLeaseManager) Complete(_ context.Context, leaseID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	lease, ok := m.leases[leaseID]
	if !ok {
		return fmt.Errorf("lease not found: %s", leaseID)
	}
	if lease.Status != LeaseStatusActive {
		return fmt.Errorf("cannot complete lease in %s state", lease.Status)
	}

	lease.Status = LeaseStatusCompleted
	lease.CompletedAt = m.clock()
	return nil
}

// Extend extends the TTL of an ACTIVE lease.
func (m *InMemoryLeaseManager) Extend(_ context.Context, leaseID string, duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	lease, ok := m.leases[leaseID]
	if !ok {
		return fmt.Errorf("lease not found: %s", leaseID)
	}
	if lease.Status != LeaseStatusActive {
		return fmt.Errorf("cannot extend lease in %s state", lease.Status)
	}

	lease.ExpiresAt = lease.ExpiresAt.Add(duration)
	lease.TTL = lease.TTL + duration
	return nil
}

// Revoke terminates a lease with a reason.
func (m *InMemoryLeaseManager) Revoke(_ context.Context, leaseID string, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	lease, ok := m.leases[leaseID]
	if !ok {
		return fmt.Errorf("lease not found: %s", leaseID)
	}
	if lease.IsTerminal() {
		return fmt.Errorf("cannot revoke terminal lease in %s state", lease.Status)
	}

	lease.Status = LeaseStatusRevoked
	lease.RevokeReason = reason
	lease.CompletedAt = m.clock()
	return nil
}

// Get returns a lease by ID.
func (m *InMemoryLeaseManager) Get(_ context.Context, leaseID string) (*ExecutionLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	lease, ok := m.leases[leaseID]
	if !ok {
		return nil, nil
	}
	copy := *lease
	return &copy, nil
}

// ListActive returns all non-terminal leases.
func (m *InMemoryLeaseManager) ListActive(_ context.Context) ([]*ExecutionLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []*ExecutionLease
	for _, lease := range m.leases {
		if !lease.IsTerminal() {
			copy := *lease
			result = append(result, &copy)
		}
	}
	return result, nil
}

// ExpireStale transitions any ACTIVE lease past its ExpiresAt to EXPIRED.
func (m *InMemoryLeaseManager) ExpireStale(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock()
	expired := 0
	for _, lease := range m.leases {
		if lease.Status == LeaseStatusActive && now.After(lease.ExpiresAt) {
			lease.Status = LeaseStatusExpired
			lease.CompletedAt = now
			expired++
		}
	}
	return expired, nil
}
