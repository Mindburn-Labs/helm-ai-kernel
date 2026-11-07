// Package pack provides deterministic pack resolution for HELM.
// Per Section 4.1 - resolves capabilities to versioned, content-addressed packs.
package pack

import (
	"context"
	"sync"
	"time"
)

// Resolver provides deterministic pack resolution.
type Resolver struct {
	registry PackRegistry
	cache    *ResolutionCache
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

// ResolutionCache caches resolution results.
type ResolutionCache struct {
	entries map[string]*ResolutionResult
	mu      sync.RWMutex
}

// InMemoryRegistry is a simple in-memory pack registry for testing.
type InMemoryRegistry struct {
	packs map[string]*Pack
	mu    sync.RWMutex
}
