package csr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/regwatch"
)

// Standard errors for registry operations.
var (
	ErrSourceNotFound = errors.New("compliance source not found")
	ErrSourceExists   = errors.New("compliance source already exists")
	ErrInvalidSource  = errors.New("invalid compliance source")
)

// ComplianceSourceRegistry is the canonical registry for all compliance source connectors.
// One registry in-repo (and later in the cloud control plane) that defines every source connector.
type ComplianceSourceRegistry interface {
	// Register adds a compliance source to the registry.
	Register(source *ComplianceSource) error

	// Get retrieves a source by its unique ID.
	Get(sourceID string) (*ComplianceSource, error)

	// ListByClass returns all sources for a given compliance domain.
	ListByClass(class SourceClass) []*ComplianceSource

	// ListByJurisdiction returns all sources applicable to a jurisdiction.
	ListByJurisdiction(code jkg.JurisdictionCode) []*ComplianceSource

	// ListAll returns every registered source.
	ListAll() []*ComplianceSource

	// Unregister removes a source from the registry.
	Unregister(sourceID string) error

	// Validate checks a source definition for completeness and correctness.
	Validate(source *ComplianceSource) error

	// Snapshot returns a deterministic, hashable snapshot of the registry.
	Snapshot() (*RegistrySnapshot, error)

	// RegisterAdapter associates a SourceAdapter with a source ID.
	RegisterAdapter(sourceID string, adapter regwatch.SourceAdapter) error

	// ResolveAdapter returns the adapter wired to a given source.
	ResolveAdapter(sourceID string) (regwatch.SourceAdapter, error)
}

// RegistrySnapshot is a deterministic, hashable representation of the registry.
type RegistrySnapshot struct {
	Sources []ComplianceSource `json:"sources"` // Sorted by SourceID
	Hash    string             `json:"hash"`    // SHA-256 of canonical JSON
	Count   int                `json:"count"`
}

// InMemoryCSR is a thread-safe in-memory implementation of ComplianceSourceRegistry.
type InMemoryCSR struct {
	mu       sync.RWMutex
	sources  map[string]*ComplianceSource
	adapters map[string]regwatch.SourceAdapter
}

// NewInMemoryCSR creates a new in-memory compliance source registry.
func NewInMemoryCSR() *InMemoryCSR {
	return &InMemoryCSR{
		sources:  make(map[string]*ComplianceSource),
		adapters: make(map[string]regwatch.SourceAdapter),
	}
}

// Register adds a compliance source to the registry after validation.
func (r *InMemoryCSR) Register(source *ComplianceSource) error {
	if err := r.Validate(source); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSource, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sources[source.SourceID]; exists {
		return fmt.Errorf("%w: %s", ErrSourceExists, source.SourceID)
	}

	r.sources[source.SourceID] = source
	return nil
}

// Get retrieves a source by its unique ID.
func (r *InMemoryCSR) Get(sourceID string) (*ComplianceSource, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	source, ok := r.sources[sourceID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSourceNotFound, sourceID)
	}
	return source, nil
}

// ListByClass returns all sources for a given compliance domain.
func (r *InMemoryCSR) ListByClass(class SourceClass) []*ComplianceSource {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*ComplianceSource
	for _, s := range r.sources {
		if s.Class == class {
			result = append(result, s)
		}
	}
	return result
}

// ListByJurisdiction returns all sources applicable to a jurisdiction.
func (r *InMemoryCSR) ListByJurisdiction(code jkg.JurisdictionCode) []*ComplianceSource {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*ComplianceSource
	for _, s := range r.sources {
		if s.Jurisdiction == code {
			result = append(result, s)
		}
	}
	return result
}

// ListAll returns every registered source.
func (r *InMemoryCSR) ListAll() []*ComplianceSource {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*ComplianceSource, 0, len(r.sources))
	for _, s := range r.sources {
		result = append(result, s)
	}
	return result
}

// Unregister removes a source from the registry.
func (r *InMemoryCSR) Unregister(sourceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sources[sourceID]; !exists {
		return fmt.Errorf("%w: %s", ErrSourceNotFound, sourceID)
	}

	delete(r.sources, sourceID)
	return nil
}

// Validate checks a source definition for completeness and correctness.
func (r *InMemoryCSR) Validate(source *ComplianceSource) error {
	if source == nil {
		return errors.New("source is nil")
	}
	if source.SourceID == "" {
		return errors.New("source_id is required")
	}
	if source.Name == "" {
		return errors.New("name is required")
	}
	if source.Class == "" {
		return errors.New("class is required")
	}
	if !isValidSourceClass(source.Class) {
		return fmt.Errorf("invalid source class: %s", source.Class)
	}
	if source.FetchMethod == "" {
		return errors.New("fetch_method is required")
	}
	if source.EndpointURL == "" {
		return errors.New("endpoint_url is required")
	}
	if source.Trust.HashChain == "" && source.Trust.HashChainPolicy == "" {
		return errors.New("trust.hash_chain is required (HashChain or legacy HashChainPolicy)")
	}
	return nil
}

// isValidSourceClass checks if a class value is one of the defined enums.
func isValidSourceClass(class SourceClass) bool {
	for _, c := range AllSourceClasses() {
		if c == class {
			return true
		}
	}
	return false
}

// Snapshot returns a deterministic, hashable snapshot of the registry.
func (r *InMemoryCSR) Snapshot() (*RegistrySnapshot, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sources := make([]ComplianceSource, 0, len(r.sources))
	for _, s := range r.sources {
		sources = append(sources, *s)
	}

	// Deterministic sort by SourceID
	sort.Slice(sources, func(i, j int) bool {
		return sources[i].SourceID < sources[j].SourceID
	})

	// Compute hash over sorted sources
	data, err := json.Marshal(sources)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	h := sha256.Sum256(data)
	hash := hex.EncodeToString(h[:])

	return &RegistrySnapshot{
		Sources: sources,
		Hash:    hash,
		Count:   len(sources),
	}, nil
}

// RegisterAdapter associates a SourceAdapter with a source ID.
func (r *InMemoryCSR) RegisterAdapter(sourceID string, adapter regwatch.SourceAdapter) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if adapter == nil {
		return fmt.Errorf("adapter is nil")
	}
	if sourceID == "" {
		return fmt.Errorf("sourceID is empty")
	}

	r.adapters[sourceID] = adapter
	return nil
}

// ResolveAdapter returns the adapter wired to a given source.
func (r *InMemoryCSR) ResolveAdapter(sourceID string) (regwatch.SourceAdapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	adapter, ok := r.adapters[sourceID]
	if !ok {
		return nil, fmt.Errorf("no adapter registered for source %q", sourceID)
	}
	return adapter, nil
}
