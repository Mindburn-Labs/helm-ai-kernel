package truth

import (
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// UnknownRegistry tracks unresolved questions that affect runtime, policy, or replay fidelity.
type UnknownRegistry interface {
	// Register adds a new unknown. Returns error if ID already exists.
	Register(unknown *contracts.Unknown) error

	// Resolve marks an unknown as resolved with a resolution description.
	Resolve(unknownID string, resolution string) error

	// Get returns an unknown by ID. Returns nil if not found.
	Get(unknownID string) (*TrackedUnknown, error)

	// ListBlocking returns all unknowns that block a specific step.
	ListBlocking(stepID string) ([]*TrackedUnknown, error)

	// ListAll returns all tracked unknowns.
	ListAll() ([]*TrackedUnknown, error)

	// ListUnresolved returns only unresolved unknowns.
	ListUnresolved() ([]*TrackedUnknown, error)
}

// TrackedUnknown wraps a contracts.Unknown with registry metadata.
type TrackedUnknown struct {
	contracts.Unknown

	// Resolved indicates whether this unknown has been resolved.
	Resolved bool `json:"resolved"`

	// Resolution describes how the unknown was resolved.
	Resolution string `json:"resolution,omitempty"`

	// RegisteredAt is when the unknown was first registered.
	RegisteredAt time.Time `json:"registered_at"`

	// ResolvedAt is when the unknown was resolved.
	ResolvedAt time.Time `json:"resolved_at,omitempty"`
}

// InMemoryUnknownRegistry is a thread-safe in-memory implementation of UnknownRegistry.
type InMemoryUnknownRegistry struct {
	mu       sync.RWMutex
	unknowns map[string]*TrackedUnknown
	clock    func() time.Time
}

// NewInMemoryUnknownRegistry creates a new in-memory unknown registry.
func NewInMemoryUnknownRegistry() *InMemoryUnknownRegistry {
	return &InMemoryUnknownRegistry{
		unknowns: make(map[string]*TrackedUnknown),
		clock:    time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (r *InMemoryUnknownRegistry) WithClock(clock func() time.Time) *InMemoryUnknownRegistry {
	r.clock = clock
	return r
}

// Register adds a new unknown. Returns error if ID already exists.
func (r *InMemoryUnknownRegistry) Register(unknown *contracts.Unknown) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.unknowns[unknown.ID]; exists {
		return fmt.Errorf("unknown already registered: %s", unknown.ID)
	}

	r.unknowns[unknown.ID] = &TrackedUnknown{
		Unknown:      *unknown,
		RegisteredAt: r.clock(),
	}
	return nil
}

// Resolve marks an unknown as resolved.
func (r *InMemoryUnknownRegistry) Resolve(unknownID string, resolution string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	tracked, ok := r.unknowns[unknownID]
	if !ok {
		return fmt.Errorf("unknown not found: %s", unknownID)
	}
	if tracked.Resolved {
		return fmt.Errorf("unknown already resolved: %s", unknownID)
	}

	tracked.Resolved = true
	tracked.Resolution = resolution
	tracked.ResolvedAt = r.clock()
	return nil
}

// Get returns a tracked unknown by ID.
func (r *InMemoryUnknownRegistry) Get(unknownID string) (*TrackedUnknown, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tracked, ok := r.unknowns[unknownID]
	if !ok {
		return nil, nil
	}
	copy := *tracked
	return &copy, nil
}

// ListBlocking returns all unknowns that block a specific step.
func (r *InMemoryUnknownRegistry) ListBlocking(stepID string) ([]*TrackedUnknown, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*TrackedUnknown
	for _, tracked := range r.unknowns {
		if tracked.Resolved {
			continue
		}
		for _, sid := range tracked.BlockingStepIDs {
			if sid == stepID {
				copy := *tracked
				result = append(result, &copy)
				break
			}
		}
	}
	return result, nil
}

// ListAll returns all tracked unknowns.
func (r *InMemoryUnknownRegistry) ListAll() ([]*TrackedUnknown, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*TrackedUnknown, 0, len(r.unknowns))
	for _, tracked := range r.unknowns {
		copy := *tracked
		result = append(result, &copy)
	}
	return result, nil
}

// ListUnresolved returns only unresolved unknowns.
func (r *InMemoryUnknownRegistry) ListUnresolved() ([]*TrackedUnknown, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*TrackedUnknown
	for _, tracked := range r.unknowns {
		if !tracked.Resolved {
			copy := *tracked
			result = append(result, &copy)
		}
	}
	return result, nil
}
