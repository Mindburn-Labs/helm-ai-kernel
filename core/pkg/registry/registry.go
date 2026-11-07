package registry

import (
	"errors"
	"sync"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/manifest"
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
