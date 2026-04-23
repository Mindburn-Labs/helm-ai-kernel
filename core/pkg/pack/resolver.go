// Package pack provides deterministic pack resolution for HELM.
// Per Section 4.1 - resolves capabilities to versioned, content-addressed packs.
package pack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Resolver provides deterministic pack resolution.
type Resolver struct {
	registry PackRegistry
	cache    *ResolutionCache
}

// NewResolver creates a new pack resolver.
func NewResolver(registry PackRegistry) *Resolver {
	return &Resolver{
		registry: registry,
		cache:    NewResolutionCache(),
	}
}

// PackRegistry is the interface for pack storage.
type PackRegistry interface {
	GetPack(ctx context.Context, id string) (*Pack, error)
	FindByCapability(ctx context.Context, capability string) ([]Pack, error)
	ListVersions(ctx context.Context, packName string) ([]PackVersion, error)
}

// ResolutionRequest specifies what capabilities need to be resolved.
type ResolutionRequest struct {
	RequestID    string                `json:"request_id"`
	Capabilities []string              `json:"capabilities"`
	Constraints  ResolutionConstraints `json:"constraints"`
	Context      ResolutionContext     `json:"context,omitempty"`
}

// ResolutionConstraints control the resolution process.
type ResolutionConstraints struct {
	AllowPrerelease    bool              `json:"allow_prerelease"`
	PreferStable       bool              `json:"prefer_stable"`
	PinnedVersions     map[string]string `json:"pinned_versions,omitempty"`
	ExcludedPacks      []string          `json:"excluded_packs,omitempty"`
	MaxDependencyDepth int               `json:"max_dependency_depth"`
}

// DefaultConstraints returns safe default constraints.
func DefaultConstraints() ResolutionConstraints {
	return ResolutionConstraints{
		AllowPrerelease:    false,
		PreferStable:       true,
		MaxDependencyDepth: 10,
	}
}

// ResolutionContext provides additional context for resolution.
type ResolutionContext struct {
	Environment  string `json:"environment"`
	Jurisdiction string `json:"jurisdiction,omitempty"`
}

// ResolutionResult is the output of pack resolution.
type ResolutionResult struct {
	ResultID     string         `json:"result_id"`
	RequestID    string         `json:"request_id"`
	ResolvedAt   time.Time      `json:"resolved_at"`
	Packs        []ResolvedPack `json:"packs"`
	InstallOrder []string       `json:"install_order"`
	TotalHash    string         `json:"total_hash"`
	Warnings     []string       `json:"warnings,omitempty"`
}

// ResolvedPack is a pack selected for installation.
type ResolvedPack struct {
	PackID   string       `json:"pack_id"`
	Manifest PackManifest `json:"manifest"` // Full manifest
	// Name         string   `json:"name"` // Deprecated for direct access, keep for compatibility if needed or check usage
	// Version      string   `json:"version"`
	ContentHash string `json:"content_hash"`
	// Capabilities []string `json:"capabilities"` // Calculated from Manifest
	Reason string `json:"reason"` // why selected
}

// Resolve performs deterministic pack resolution.
func (r *Resolver) Resolve(ctx context.Context, req *ResolutionRequest) (*ResolutionResult, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	if len(req.Capabilities) == 0 {
		return nil, fmt.Errorf("no capabilities requested")
	}

	// Check cache
	cacheKey := r.computeCacheKey(req)
	if cached := r.cache.Get(cacheKey); cached != nil {
		return cached, nil
	}

	result := &ResolutionResult{
		ResultID:   uuid.New().String(),
		RequestID:  req.RequestID,
		ResolvedAt: time.Now(),
		Packs:      []ResolvedPack{},
		Warnings:   []string{},
	}

	// Collect packs for each capability
	packMap := make(map[string]ResolvedPack)

	for _, cap := range req.Capabilities {
		pack, err := r.resolveCapability(ctx, cap, req.Constraints)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve capability %s: %w", cap, err)
		}

		// Avoid duplicates
		if _, exists := packMap[pack.PackID]; !exists {
			packMap[pack.PackID] = *pack
		}
	}

	// Convert to slice and sort for determinism
	for _, pack := range packMap {
		result.Packs = append(result.Packs, pack)
	}
	sort.Slice(result.Packs, func(i, j int) bool {
		return result.Packs[i].Manifest.Name < result.Packs[j].Manifest.Name
	})

	// Compute install order (topological sort would go here)
	result.InstallOrder = make([]string, len(result.Packs))
	for i, pack := range result.Packs {
		result.InstallOrder[i] = pack.PackID
	}

	// Compute total hash for reproducibility
	result.TotalHash = r.computeTotalHash(result.Packs)

	// Cache result
	r.cache.Set(cacheKey, result)

	return result, nil
}

// resolveCapability finds the best pack for a capability.
func (r *Resolver) resolveCapability(ctx context.Context, capability string, constraints ResolutionConstraints) (*ResolvedPack, error) {
	// Check for pinned version
	if pinned, ok := constraints.PinnedVersions[capability]; ok {
		pack, err := r.registry.GetPack(ctx, pinned)
		if err != nil {
			return nil, err
		}
		return &ResolvedPack{
			PackID:      pack.PackID,
			Manifest:    pack.Manifest,
			ContentHash: pack.ContentHash,
			Reason:      "pinned version",
		}, nil
	}

	// Find candidates
	candidates, err := r.registry.FindByCapability(ctx, capability)
	if err != nil {
		return nil, err
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no pack provides capability: %s", capability)
	}

	// Filter excluded
	var filtered []Pack
	for _, pack := range candidates {
		excluded := false
		for _, excl := range constraints.ExcludedPacks {
			if pack.Manifest.Name == excl {
				excluded = true
				break
			}
		}
		if !excluded {
			filtered = append(filtered, pack)
		}
	}

	if len(filtered) == 0 {
		return nil, fmt.Errorf("all packs for capability %s are excluded", capability)
	}

	// Select best candidate (prefer stable, latest version)
	best := filtered[0]
	for _, pack := range filtered[1:] {
		if pack.Manifest.Version > best.Manifest.Version { // Simplified comparison
			best = pack
		}
	}

	return &ResolvedPack{
		PackID:      best.PackID,
		Manifest:    best.Manifest,
		ContentHash: best.ContentHash,
		Reason:      fmt.Sprintf("best match for %s", capability),
	}, nil
}

// computeCacheKey generates a deterministic cache key.
func (r *Resolver) computeCacheKey(req *ResolutionRequest) string {
	// Sort capabilities for determinism
	caps := make([]string, len(req.Capabilities))
	copy(caps, req.Capabilities)
	sort.Strings(caps)

	data, _ := json.Marshal(map[string]interface{}{
		"capabilities": caps,
		"constraints":  req.Constraints,
	})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:16])
}

// computeTotalHash creates a hash of all resolved packs.
func (r *Resolver) computeTotalHash(packs []ResolvedPack) string {
	hashes := make([]string, 0, len(packs))
	for _, pack := range packs {
		hashes = append(hashes, pack.ContentHash)
	}
	sort.Strings(hashes)

	data, _ := json.Marshal(hashes)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// ResolutionCache caches resolution results.
type ResolutionCache struct {
	entries map[string]*ResolutionResult
	mu      sync.RWMutex
}

// NewResolutionCache creates a new cache.
func NewResolutionCache() *ResolutionCache {
	return &ResolutionCache{
		entries: make(map[string]*ResolutionResult),
	}
}

// Get retrieves a cached result.
func (c *ResolutionCache) Get(key string) *ResolutionResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[key]
}

// Set stores a result in the cache.
func (c *ResolutionCache) Set(key string, result *ResolutionResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = result
}

// InMemoryRegistry is a simple in-memory pack registry for testing.
type InMemoryRegistry struct {
	packs map[string]*Pack
	mu    sync.RWMutex
}

// NewInMemoryRegistry creates a new in-memory registry.
func NewInMemoryRegistry() *InMemoryRegistry {
	return &InMemoryRegistry{
		packs: make(map[string]*Pack),
	}
}

// Register adds a pack to the registry.
func (r *InMemoryRegistry) Register(pack *Pack) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.packs[pack.PackID] = pack
}

// GetPack retrieves a pack by ID.
func (r *InMemoryRegistry) GetPack(ctx context.Context, id string) (*Pack, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pack, ok := r.packs[id]
	if !ok {
		return nil, fmt.Errorf("pack not found: %s", id)
	}
	return pack, nil
}

// FindByCapability finds packs providing a capability.
func (r *InMemoryRegistry) FindByCapability(ctx context.Context, capability string) ([]Pack, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Pack
	for _, pack := range r.packs {
		for _, cap := range pack.Manifest.Capabilities {
			if cap == capability {
				result = append(result, *pack)
				break
			}
		}
	}
	return result, nil
}

// ListVersions lists all versions of a pack.
func (r *InMemoryRegistry) ListVersions(ctx context.Context, packName string) ([]PackVersion, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var versions []PackVersion
	for _, pack := range r.packs {
		if pack.Manifest.Name == packName {
			versions = append(versions, PackVersion{
				PackName:    pack.Manifest.Name,
				Version:     pack.Manifest.Version,
				ContentHash: pack.ContentHash,
				ReleasedAt:  pack.CreatedAt,
			})
		}
	}
	return versions, nil
}
