package registry

import (
	"errors"
	"hash/crc32"
	"strings"
	"sync"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/manifest"
)

var ErrModuleNotFound = errors.New("module not found")

// Registry acts as the Source of Truth for installed capabilities.
type Registry interface {
	Register(bundle *manifest.Bundle) error
	Get(name string) (*manifest.Bundle, error)
	GetForUser(name, userID string) (*manifest.Bundle, error)
	SetRollout(name string, canaryBundle *manifest.Bundle, percentage int) error
	// List returns all installed bundles.
	List() []*manifest.Bundle
	// Unregister removes a bundle from the registry (e.g. for revocation).
	Unregister(name string) error
	// Install records a pack installation for a tenant.
	Install(tenantID, packID string) error
}

type moduleState struct {
	stable       *manifest.Bundle
	canary       *manifest.Bundle
	canaryMillis int // 0-10000 (0% to 100%)
}

// InMemoryRegistry is a thread-safe in-memory implementation.
type InMemoryRegistry struct {
	mu      sync.RWMutex
	modules map[string]*moduleState
}

func NewInMemoryRegistry() *InMemoryRegistry {
	return &InMemoryRegistry{
		modules: make(map[string]*moduleState),
	}
}

func (r *InMemoryRegistry) Register(bundle *manifest.Bundle) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if bundle == nil {
		return errors.New("nil bundle")
	}

	// Default behavior: Overwrite stable, clear canary
	r.modules[bundle.Manifest.Name] = &moduleState{
		stable: bundle,
	}
	return nil
}

func (r *InMemoryRegistry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.modules[name]; !ok {
		return ErrModuleNotFound
	}
	delete(r.modules, name)
	return nil
}

// SetRollout configures a canary deployment.
func (r *InMemoryRegistry) SetRollout(name string, canaryBundle *manifest.Bundle, percentage int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, ok := r.modules[name]
	if !ok {
		return ErrModuleNotFound
	}

	if percentage < 0 || percentage > 100 {
		return errors.New("percentage must be 0-100")
	}

	state.canary = canaryBundle
	state.canaryMillis = percentage * 100 // precision 0.01%
	return nil
}

func (r *InMemoryRegistry) Get(name string) (*manifest.Bundle, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if state, ok := r.modules[name]; ok {
		return state.stable, nil
	}
	return nil, ErrModuleNotFound
}

func (r *InMemoryRegistry) GetForUser(name, userID string) (*manifest.Bundle, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	state, ok := r.modules[name]
	if !ok {
		return nil, ErrModuleNotFound
	}

	// Canary Logic
	if state.canary != nil && state.canaryMillis > 0 {
		hash := crc32.ChecksumIEEE([]byte(strings.ToLower(userID)))
		// Map hash to 0-10000
		userSlot := int(hash % 10000)
		if userSlot < state.canaryMillis {
			return state.canary, nil
		}
	}

	return state.stable, nil
}

func (r *InMemoryRegistry) List() []*manifest.Bundle {
	r.mu.RLock()
	defer r.mu.RUnlock()

	list := make([]*manifest.Bundle, 0, len(r.modules))
	for _, s := range r.modules {
		list = append(list, s.stable)
	}
	return list
}

func (r *InMemoryRegistry) Install(tenantID, packID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.modules[packID]; !ok {
		return ErrModuleNotFound
	}
	return nil
}
