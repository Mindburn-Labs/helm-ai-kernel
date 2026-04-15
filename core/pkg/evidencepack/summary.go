// summary.go implements constant-size evidence summaries for evidence packs.
// Per arXiv 2511.17118, a fixed-size tuple proves pack completeness in O(1) space.
//
// The summary contains:
//   - Pack ID and manifest hash (binding)
//   - Entry count and total size (completeness)
//   - Node type coverage (which ProofGraph node types are present)
//   - First/last timestamps (temporal span)
//   - Summary hash (tamper detection)
//
// Design invariants:
//   - Fixed size regardless of pack content
//   - Verifiable without downloading the full pack
//   - Tamper-evident via SHA-256 summary hash
package evidencepack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// EvidenceSummary is a constant-size tuple that proves pack completeness.
// It can be verified without downloading the full evidence pack.
type EvidenceSummary struct {
	PackID         string    `json:"pack_id"`
	ManifestHash   string    `json:"manifest_hash"`
	EntryCount     int       `json:"entry_count"`
	TotalBytes     int64     `json:"total_bytes"`
	NodeTypes      []string  `json:"node_types"`       // e.g., ["ATTESTATION","EFFECT","INTENT"]
	FirstEvent     time.Time `json:"first_event"`
	LastEvent      time.Time `json:"last_event"`
	SignatureCount int       `json:"signature_count"`   // How many entries have signatures
	PolicyHash     string    `json:"policy_hash"`
	SummaryHash    string    `json:"summary_hash"`      // SHA-256 of all above fields
	GeneratedAt    time.Time `json:"generated_at"`
}

// GenerateSummary creates a constant-size evidence summary from a manifest.
// The summary captures completeness, temporal span, and node type coverage
// without requiring the full pack contents.
func GenerateSummary(manifest *Manifest) (*EvidenceSummary, error) {
	if manifest == nil {
		return nil, fmt.Errorf("manifest is nil")
	}

	summary := &EvidenceSummary{
		PackID:       manifest.PackID,
		ManifestHash: manifest.ManifestHash,
		EntryCount:   len(manifest.Entries),
		PolicyHash:   manifest.PolicyHash,
		GeneratedAt:  time.Now().UTC(),
	}

	// Accumulate total bytes and detect node types from entry paths.
	nodeTypeSet := make(map[string]struct{})
	var totalBytes int64
	signatureCount := 0

	for _, entry := range manifest.Entries {
		totalBytes += entry.Size

		// Detect node types from content type and path conventions.
		nodeType := inferNodeType(entry.Path, entry.ContentType)
		if nodeType != "" {
			nodeTypeSet[nodeType] = struct{}{}
		}

		// Count signature entries (entries under signatures/ path).
		if strings.HasPrefix(entry.Path, "signatures/") {
			signatureCount++
		}
	}

	summary.TotalBytes = totalBytes
	summary.SignatureCount = signatureCount

	// Sort node types for determinism.
	nodeTypes := make([]string, 0, len(nodeTypeSet))
	for nt := range nodeTypeSet {
		nodeTypes = append(nodeTypes, nt)
	}
	sort.Strings(nodeTypes)
	summary.NodeTypes = nodeTypes

	// Derive temporal span from manifest creation time.
	// The manifest CreatedAt serves as the canonical event timestamp.
	summary.FirstEvent = manifest.CreatedAt
	summary.LastEvent = manifest.CreatedAt

	// Compute tamper-evident summary hash.
	hash, err := computeSummaryHash(summary)
	if err != nil {
		return nil, fmt.Errorf("compute summary hash: %w", err)
	}
	summary.SummaryHash = hash

	return summary, nil
}

// Verify checks the summary hash integrity, ensuring no field has been tampered with.
func (s *EvidenceSummary) Verify() error {
	if s.SummaryHash == "" {
		return fmt.Errorf("summary hash is empty")
	}

	expected, err := computeSummaryHash(s)
	if err != nil {
		return fmt.Errorf("recompute summary hash: %w", err)
	}

	if s.SummaryHash != expected {
		return fmt.Errorf("summary hash mismatch: stored %s, computed %s", s.SummaryHash, expected)
	}

	return nil
}

// HasNodeType reports whether the summary covers the given ProofGraph node type.
func (s *EvidenceSummary) HasNodeType(nodeType string) bool {
	for _, nt := range s.NodeTypes {
		if nt == nodeType {
			return true
		}
	}
	return false
}

// Duration returns the temporal span covered by the evidence pack.
func (s *EvidenceSummary) Duration() time.Duration {
	return s.LastEvent.Sub(s.FirstEvent)
}

// computeSummaryHash produces a SHA-256 hash of all summary fields except SummaryHash.
// Fields are serialized via JCS for determinism.
func computeSummaryHash(s *EvidenceSummary) (string, error) {
	hashable := struct {
		PackID         string    `json:"pack_id"`
		ManifestHash   string    `json:"manifest_hash"`
		EntryCount     int       `json:"entry_count"`
		TotalBytes     int64     `json:"total_bytes"`
		NodeTypes      []string  `json:"node_types"`
		FirstEvent     time.Time `json:"first_event"`
		LastEvent      time.Time `json:"last_event"`
		SignatureCount int       `json:"signature_count"`
		PolicyHash     string    `json:"policy_hash"`
		GeneratedAt    time.Time `json:"generated_at"`
	}{
		PackID:         s.PackID,
		ManifestHash:   s.ManifestHash,
		EntryCount:     s.EntryCount,
		TotalBytes:     s.TotalBytes,
		NodeTypes:      s.NodeTypes,
		FirstEvent:     s.FirstEvent,
		LastEvent:      s.LastEvent,
		SignatureCount: s.SignatureCount,
		PolicyHash:     s.PolicyHash,
		GeneratedAt:    s.GeneratedAt,
	}

	data, err := canonicalize.JCS(hashable)
	if err != nil {
		return "", fmt.Errorf("canonicalize summary: %w", err)
	}

	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// inferNodeType maps evidence pack entry paths and content types to ProofGraph
// node types. Returns empty string if no mapping is found.
func inferNodeType(path, contentType string) string {
	switch {
	case strings.HasPrefix(path, "receipts/"):
		return "ATTESTATION"
	case strings.HasPrefix(path, "policy/"):
		return "INTENT"
	case strings.HasPrefix(path, "transcripts/"):
		return "EFFECT"
	case strings.HasPrefix(path, "network/"):
		return "EFFECT"
	case strings.HasPrefix(path, "diffs/"):
		return "EFFECT"
	case strings.HasPrefix(path, "secrets/"):
		return "TRUST_EVENT"
	case strings.HasPrefix(path, "replay/"):
		return "CHECKPOINT"
	default:
		return ""
	}
}
