package policybundles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// BundleManager manages policy bundle CRUD, versioning, and assignment.
type BundleManager struct {
	store BundleStore
	clock func() time.Time
}

// NewBundleManager creates a new bundle manager.
func NewBundleManager(store BundleStore) *BundleManager {
	return &BundleManager{store: store, clock: time.Now}
}

// WithClock overrides the clock for deterministic testing.
func (m *BundleManager) WithClock(clock func() time.Time) *BundleManager {
	m.clock = clock
	return m
}

// CreateBundle creates a new policy bundle with a computed content hash.
func (m *BundleManager) CreateBundle(ctx context.Context, bundle *PolicyBundle) error {
	if bundle.BundleID == "" {
		return fmt.Errorf("bundle_id is required")
	}

	bundle.CreatedAt = m.clock().UTC()
	bundle.Status = BundleStatusDraft

	// Sort rules by priority for deterministic hashing.
	sortRules(bundle.Rules)

	hash, err := ComputeBundleHash(bundle)
	if err != nil {
		return fmt.Errorf("compute content hash: %w", err)
	}
	bundle.ContentHash = hash

	return m.store.Create(ctx, bundle)
}

// ActivateBundle transitions a bundle from draft to active.
func (m *BundleManager) ActivateBundle(ctx context.Context, bundleID string) error {
	bundle, err := m.store.Get(ctx, bundleID)
	if err != nil {
		return err
	}
	if bundle.Status != BundleStatusDraft {
		return fmt.Errorf("only draft bundles can be activated, current status: %s", bundle.Status)
	}
	now := m.clock().UTC()
	bundle.Status = BundleStatusActive
	bundle.ActivatedAt = &now
	return m.store.Update(ctx, bundle)
}

// DeprecateBundle transitions a bundle from active to deprecated.
func (m *BundleManager) DeprecateBundle(ctx context.Context, bundleID string) error {
	bundle, err := m.store.Get(ctx, bundleID)
	if err != nil {
		return err
	}
	if bundle.Status != BundleStatusActive {
		return fmt.Errorf("only active bundles can be deprecated, current status: %s", bundle.Status)
	}
	bundle.Status = BundleStatusDeprecated
	return m.store.Update(ctx, bundle)
}

// NewVersion creates a new version of an existing bundle with updated rules.
// The new version gets a fresh content hash.
func (m *BundleManager) NewVersion(ctx context.Context, bundleID string, rules []PolicyRule) (*PolicyBundle, error) {
	existing, err := m.store.Get(ctx, bundleID)
	if err != nil {
		return nil, err
	}

	newBundle := &PolicyBundle{
		BundleID:     existing.BundleID,
		Name:         existing.Name,
		Description:  existing.Description,
		Jurisdiction: existing.Jurisdiction,
		Category:     existing.Category,
		Version:      existing.Version + 1,
		Rules:        rules,
		Status:       BundleStatusDraft,
		CreatedAt:    m.clock().UTC(),
	}

	sortRules(newBundle.Rules)

	hash, err := ComputeBundleHash(newBundle)
	if err != nil {
		return nil, fmt.Errorf("compute content hash: %w", err)
	}
	newBundle.ContentHash = hash

	// Update in-place (same bundle ID, new version).
	if err := m.store.Update(ctx, newBundle); err != nil {
		return nil, err
	}

	return newBundle, nil
}

// GetBundle retrieves a bundle by ID.
func (m *BundleManager) GetBundle(ctx context.Context, bundleID string) (*PolicyBundle, error) {
	return m.store.Get(ctx, bundleID)
}

// ListBundles lists bundles, optionally filtered by jurisdiction.
func (m *BundleManager) ListBundles(ctx context.Context, jurisdiction string) ([]*PolicyBundle, error) {
	return m.store.List(ctx, jurisdiction)
}

// AssignBundle assigns a bundle to a tenant (optionally scoped to a workspace).
func (m *BundleManager) AssignBundle(ctx context.Context, assignment *BundleAssignment) error {
	// Verify the bundle exists.
	if _, err := m.store.Get(ctx, assignment.BundleID); err != nil {
		return fmt.Errorf("bundle not found: %w", err)
	}
	assignment.CreatedAt = m.clock().UTC()
	return m.store.CreateAssignment(ctx, assignment)
}

// ListAssignments lists bundle assignments for a tenant.
func (m *BundleManager) ListAssignments(ctx context.Context, tenantID string) ([]*BundleAssignment, error) {
	return m.store.ListAssignments(ctx, tenantID)
}

// RemoveAssignment removes a bundle assignment.
func (m *BundleManager) RemoveAssignment(ctx context.Context, assignmentID string) error {
	return m.store.RemoveAssignment(ctx, assignmentID)
}

// ComputeBundleHash computes a deterministic content hash for a policy bundle.
// Uses JCS canonicalization for cross-platform determinism.
func ComputeBundleHash(bundle *PolicyBundle) (string, error) {
	// Hash only the semantic content, not metadata like status, timestamps, or hash itself.
	hashable := struct {
		BundleID     string       `json:"bundle_id"`
		Name         string       `json:"name"`
		Jurisdiction string       `json:"jurisdiction"`
		Category     string       `json:"category"`
		Version      int          `json:"version"`
		Rules        []PolicyRule `json:"rules"`
	}{
		BundleID:     bundle.BundleID,
		Name:         bundle.Name,
		Jurisdiction: bundle.Jurisdiction,
		Category:     bundle.Category,
		Version:      bundle.Version,
		Rules:        bundle.Rules,
	}

	data, err := canonicalize.JCS(hashable)
	if err != nil {
		return "", fmt.Errorf("JCS canonicalization failed: %w", err)
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// sortRules sorts rules by priority (ascending) for deterministic ordering.
func sortRules(rules []PolicyRule) {
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})
}
