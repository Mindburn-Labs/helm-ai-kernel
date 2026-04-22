// Package evidencepack provides deterministic evidence pack building, archiving,
// and storage for HELM. An evidence pack is a content-addressed, tamper-evident
// archive containing all receipts, policy decisions, tool transcripts, and
// provenance data for a single execution.
package evidencepack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// ManifestVersion is the current manifest schema version.
const ManifestVersion = "1.0.0"

// Manifest is the canonical manifest for an evidence pack.
// Entries are sorted lexicographically by path. Each entry has a content hash.
// The manifest hash is computed over the sorted canonical JSON representation.
type Manifest struct {
	Version      string          `json:"version"`
	PackID       string          `json:"pack_id"`
	CreatedAt    time.Time       `json:"created_at"`
	ActorDID     string          `json:"actor_did"`
	IntentID     string          `json:"intent_id"`
	PolicyHash   string          `json:"policy_hash"`
	Entries      []ManifestEntry `json:"entries"`
	ManifestHash string          `json:"manifest_hash"`
}

// ManifestEntry describes a single file in the evidence pack.
type ManifestEntry struct {
	Path        string `json:"path"`
	ContentHash string `json:"content_hash"` // sha256:hex
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
}

// ComputeManifestHash computes the deterministic hash of the manifest.
// The hash covers all fields except manifest_hash itself.
func ComputeManifestHash(m *Manifest) (string, error) {
	// Sort entries by path for determinism
	sorted := make([]ManifestEntry, len(m.Entries))
	copy(sorted, m.Entries)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})

	hashable := struct {
		Version    string          `json:"version"`
		PackID     string          `json:"pack_id"`
		CreatedAt  time.Time       `json:"created_at"`
		ActorDID   string          `json:"actor_did"`
		IntentID   string          `json:"intent_id"`
		PolicyHash string          `json:"policy_hash"`
		Entries    []ManifestEntry `json:"entries"`
	}{
		Version:    m.Version,
		PackID:     m.PackID,
		CreatedAt:  m.CreatedAt,
		ActorDID:   m.ActorDID,
		IntentID:   m.IntentID,
		PolicyHash: m.PolicyHash,
		Entries:    sorted,
	}

	data, err := canonicalize.JCS(hashable)
	if err != nil {
		return "", fmt.Errorf("canonicalize manifest for hashing: %w", err)
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// HashContent computes the SHA256 hash of content bytes.
func HashContent(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}
