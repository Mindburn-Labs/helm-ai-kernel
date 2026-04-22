// Package registry - pack_registry.go
// Provides pack publishing and marketplace registry for HELM.
// Per Section 5 - enables publishing, searching, and retrieving verified packs.

package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jcs"
)

// PackState represents the lifecycle state of a pack in the registry.
type PackState string

const (
	PackStatePublished  PackState = "published"
	PackStateVerified   PackState = "verified"
	PackStateSigned     PackState = "signed"
	PackStateActive     PackState = "active"
	PackStateDeprecated PackState = "deprecated"
)

// PackEntry is a registered pack in the registry.
type PackEntry struct {
	PackID       string                 `json:"pack_id"`
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Description  string                 `json:"description"`
	Capabilities []string               `json:"capabilities"`
	State        PackState              `json:"state"`
	ContentHash  string                 `json:"content_hash"`
	Signatures   []PackSignature        `json:"signatures"`
	PublishedAt  time.Time              `json:"published_at"`
	PublishedBy  string                 `json:"published_by"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// PackSignature represents a cryptographic signature on a pack.
type PackSignature struct {
	SignerID  string    `json:"signer_id"`
	Algorithm string    `json:"algorithm"`
	Signature string    `json:"signature"`
	KeyID     string    `json:"key_id"`
	SignedAt  time.Time `json:"signed_at"`
}

// PackRegistry manages pack entries with staged activation.
type PackRegistry struct {
	entries  map[string]*PackEntry // packID -> entry
	byName   map[string][]string   // name -> list of packIDs (all versions)
	byCap    map[string][]string   // capability -> list of packIDs
	verifier PackSignatureVerifier
	mu       sync.RWMutex
}

// PackSignatureVerifier verifies pack signatures.
type PackSignatureVerifier interface {
	VerifyPackSignature(contentHash string, signature *PackSignature) (bool, error)
}

// NewPackRegistry creates a new pack registry.
func NewPackRegistry(verifier PackSignatureVerifier) *PackRegistry {
	return &PackRegistry{
		entries:  make(map[string]*PackEntry),
		byName:   make(map[string][]string),
		byCap:    make(map[string][]string),
		verifier: verifier,
	}
}

// Publish adds a new pack to the registry.
// Requires at least one valid signature.
func (r *PackRegistry) Publish(entry *PackEntry) error {
	if entry == nil {
		return fmt.Errorf("entry cannot be nil")
	}
	if entry.Name == "" {
		return fmt.Errorf("pack name is required")
	}
	if entry.Version == "" {
		return fmt.Errorf("pack version is required")
	}
	if entry.ContentHash == "" {
		return fmt.Errorf("content hash is required")
	}
	if len(entry.Signatures) == 0 {
		return fmt.Errorf("at least one signature is required")
	}
	if r.verifier == nil {
		return fmt.Errorf("pack signature verifier not configured (fail-closed)")
	}

	// Verify at least one signature
	verified := false
	for _, sig := range entry.Signatures {
		ok, err := r.verifier.VerifyPackSignature(entry.ContentHash, &sig)
		if err == nil && ok {
			verified = true
			break
		}
	}
	if !verified {
		return fmt.Errorf("no valid signature found")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Generate pack ID if not set
	if entry.PackID == "" {
		entry.PackID = uuid.New().String()
	}

	entry.State = PackStatePublished
	entry.PublishedAt = time.Now()

	// Store entry
	r.entries[entry.PackID] = entry

	// Index by name
	r.byName[entry.Name] = append(r.byName[entry.Name], entry.PackID)

	// Index by capabilities
	for _, cap := range entry.Capabilities {
		r.byCap[cap] = append(r.byCap[cap], entry.PackID)
	}

	return nil
}

// Get retrieves a pack by ID.
func (r *PackRegistry) Get(packID string) (*PackEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.entries[packID]
	return entry, ok
}

// GetByNameVersion retrieves a pack by name and version.
func (r *PackRegistry) GetByNameVersion(name, version string) (*PackEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	packIDs, ok := r.byName[name]
	if !ok {
		return nil, false
	}

	for _, id := range packIDs {
		entry := r.entries[id]
		if entry.Version == version {
			return entry, true
		}
	}
	return nil, false
}

// PackSearchQuery defines search criteria.
type PackSearchQuery struct {
	Name       string      `json:"name,omitempty"`
	Capability string      `json:"capability,omitempty"`
	States     []PackState `json:"states,omitempty"`
	Limit      int         `json:"limit,omitempty"`
}

// PackSearchResult is the result of a search.
type PackSearchResult struct {
	Entries    []*PackEntry    `json:"entries"`
	TotalCount int             `json:"total_count"`
	Query      PackSearchQuery `json:"query"`
}

// Search finds packs matching criteria with deterministic ordering.
//
//nolint:gocognit // complexity acceptable
func (r *PackRegistry) Search(query PackSearchQuery) *PackSearchResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := &PackSearchResult{
		Entries: []*PackEntry{},
		Query:   query,
	}

	// Collect candidate pack IDs
	candidateIDs := make(map[string]bool)

	if query.Capability != "" {
		// Search by capability
		for _, id := range r.byCap[query.Capability] {
			candidateIDs[id] = true
		}
	} else if query.Name != "" {
		// Search by name
		for _, id := range r.byName[query.Name] {
			candidateIDs[id] = true
		}
	} else {
		// All entries
		for id := range r.entries {
			candidateIDs[id] = true
		}
	}

	// Filter by state
	stateFilter := make(map[PackState]bool)
	for _, s := range query.States {
		stateFilter[s] = true
	}

	for id := range candidateIDs {
		entry := r.entries[id]

		// Apply state filter
		if len(stateFilter) > 0 && !stateFilter[entry.State] {
			continue
		}

		// Apply name filter (partial match)
		if query.Name != "" && entry.Name != query.Name {
			continue
		}

		result.Entries = append(result.Entries, entry)
	}

	// Deterministic ordering: by name, then version, then packID
	sort.SliceStable(result.Entries, func(i, j int) bool {
		if result.Entries[i].Name != result.Entries[j].Name {
			return result.Entries[i].Name < result.Entries[j].Name
		}
		if result.Entries[i].Version != result.Entries[j].Version {
			return result.Entries[i].Version < result.Entries[j].Version
		}
		return result.Entries[i].PackID < result.Entries[j].PackID
	})

	result.TotalCount = len(result.Entries)

	// Apply limit
	if query.Limit > 0 && len(result.Entries) > query.Limit {
		result.Entries = result.Entries[:query.Limit]
	}

	return result
}

// ListVersions returns all versions of a pack, sorted.
func (r *PackRegistry) ListVersions(name string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	packIDs, ok := r.byName[name]
	if !ok {
		return []string{}
	}

	versions := make([]string, 0, len(packIDs))
	for _, id := range packIDs {
		versions = append(versions, r.entries[id].Version)
	}

	sort.Strings(versions)
	return versions
}

// VerifyPack re-verifies all signatures on a pack.
func (r *PackRegistry) VerifyPack(packID string) (bool, error) {
	r.mu.RLock()
	entry, ok := r.entries[packID]
	r.mu.RUnlock()

	if !ok {
		return false, fmt.Errorf("pack not found: %s", packID)
	}

	if r.verifier == nil {
		return false, fmt.Errorf("pack signature verifier not configured (fail-closed)")
	}

	for _, sig := range entry.Signatures {
		ok, err := r.verifier.VerifyPackSignature(entry.ContentHash, &sig)
		if err != nil || !ok {
			return false, fmt.Errorf("signature verification failed for signer %s", sig.SignerID)
		}
	}

	return true, nil
}

// Activate transitions a pack to active state.
// Pack must be in verified or signed state.
func (r *PackRegistry) Activate(packID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[packID]
	if !ok {
		return fmt.Errorf("pack not found: %s", packID)
	}

	// Staged activation: must be verified or signed first
	if entry.State != PackStateVerified && entry.State != PackStateSigned {
		return fmt.Errorf("pack must be verified or signed before activation, current state: %s", entry.State)
	}

	entry.State = PackStateActive
	return nil
}

// MarkVerified transitions a pack to verified state.
func (r *PackRegistry) MarkVerified(packID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[packID]
	if !ok {
		return fmt.Errorf("pack not found: %s", packID)
	}

	if entry.State != PackStatePublished {
		return fmt.Errorf("pack must be published before verification, current state: %s", entry.State)
	}

	entry.State = PackStateVerified
	return nil
}

// MarkSigned transitions a pack to signed state.
func (r *PackRegistry) MarkSigned(packID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[packID]
	if !ok {
		return fmt.Errorf("pack not found: %s", packID)
	}

	if entry.State != PackStateVerified {
		return fmt.Errorf("pack must be verified before signing, current state: %s", entry.State)
	}

	entry.State = PackStateSigned
	return nil
}

// Deprecate marks a pack as deprecated.
func (r *PackRegistry) Deprecate(packID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[packID]
	if !ok {
		return fmt.Errorf("pack not found: %s", packID)
	}

	entry.State = PackStateDeprecated
	return nil
}

// Hash computes a deterministic hash of the registry state.
func (r *PackRegistry) Hash() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Collect and sort pack entries for determinism
	entries := make([]*PackEntry, 0, len(r.entries))
	for _, entry := range r.entries {
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].PackID < entries[j].PackID
	})

	data, _ := jcs.Marshal(map[string]interface{}{
		"pack_count": len(r.entries),
		"entries":    entries,
	})

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Count returns the total number of entries.
func (r *PackRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}
