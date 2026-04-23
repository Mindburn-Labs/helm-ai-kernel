// Package context — Portable context and documentation bundles.
//
// Per HELM 2030 Spec §5.4 / §6.1.4:
//
//	HELM OSS MUST include portable context bundles, local documentation
//	bundles, and version-aware context retrieval.
//
// Resolves: GAP-A7, GAP-A8.
package context

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// ── GAP-A7: Portable Context Bundle ─────────────────────────────

// ContextBundle is a portable snapshot of organizational context.
type ContextBundle struct {
	BundleID       string                   `json:"bundle_id"`
	Version        string                   `json:"version"`
	OrgID          string                   `json:"org_id"`
	Namespaces     map[string][]BundleEntry `json:"namespaces"`
	ProvenanceHash string                   `json:"provenance_hash"`
	TTL            *time.Duration           `json:"ttl,omitempty"`
	CreatedAt      time.Time                `json:"created_at"`
	CreatedBy      string                   `json:"created_by"`
	ContentHash    string                   `json:"content_hash"`
}

// BundleEntry is a single entry within a context bundle namespace.
type BundleEntry struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	TrustLevel  string `json:"trust_level"` // "CURATED", "LEARNED", "EXTERNAL"
	Source      string `json:"source"`
	ContentHash string `json:"content_hash"`
}

// ExportBundle creates a serializable context bundle from current namespaces.
func ExportBundle(bundleID, orgID, version, creator string, namespaces map[string][]BundleEntry) (*ContextBundle, error) {
	if bundleID == "" || orgID == "" || version == "" {
		return nil, fmt.Errorf("bundle requires bundle_id, org_id, and version")
	}

	now := time.Now().UTC()
	hashInput := fmt.Sprintf("%s:%s:%s:%s", bundleID, orgID, version, now.String())
	h := sha256.Sum256([]byte(hashInput))

	return &ContextBundle{
		BundleID:    bundleID,
		Version:     version,
		OrgID:       orgID,
		Namespaces:  namespaces,
		CreatedAt:   now,
		CreatedBy:   creator,
		ContentHash: "sha256:" + hex.EncodeToString(h[:]),
	}, nil
}

// ValidateBundle checks bundle structural integrity.
func ValidateBundle(b ContextBundle) error {
	if b.BundleID == "" {
		return fmt.Errorf("bundle missing bundle_id")
	}
	if b.OrgID == "" {
		return fmt.Errorf("bundle missing org_id")
	}
	if b.Version == "" {
		return fmt.Errorf("bundle missing version")
	}
	if len(b.Namespaces) == 0 {
		return fmt.Errorf("bundle has no namespaces")
	}
	return nil
}

// ── GAP-A8: Local Documentation Bundle ───────────────────────────

// DocumentBundle packages local documentation for offline/edge use.
type DocumentBundle struct {
	BundleID    string          `json:"bundle_id"`
	Title       string          `json:"title"`
	Version     string          `json:"version"`
	Documents   []DocumentEntry `json:"documents"`
	ContentHash string          `json:"content_hash"`
	CreatedAt   time.Time       `json:"created_at"`
}

// DocumentEntry is a single document within a documentation bundle.
type DocumentEntry struct {
	Path        string `json:"path"`
	Title       string `json:"title"`
	Format      string `json:"format"` // "MARKDOWN", "HTML", "TEXT"
	Content     string `json:"content"`
	ContentHash string `json:"content_hash"`
}
