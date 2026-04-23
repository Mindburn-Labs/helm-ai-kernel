// Package memory — Provenance scoring and dual-source validation.
//
// Per HELM 2030 Spec §5.4:
//
//	Any LKS-derived claim needed for execution MUST be promoted into CKS
//	with provenance and ProofGraph linkage.
//
// Resolves: GAP-A5.
package memory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ScoreProvenance computes a provenance score (0.0–1.0) based on source diversity.
// Scoring rules:
//   - 0 sources       → 0.0
//   - 1 source        → 0.3
//   - 2 unique sources → 0.7
//   - 3+ unique sources → 1.0 (capped)
//
// Uniqueness is determined by deduplicated SourceArtifactIDs.
func ScoreProvenance(claim KnowledgeClaim) float64 {
	seen := make(map[string]struct{}, len(claim.SourceArtifactIDs))
	for _, id := range claim.SourceArtifactIDs {
		if id != "" {
			seen[id] = struct{}{}
		}
	}
	switch len(seen) {
	case 0:
		return 0.0
	case 1:
		return 0.3
	case 2:
		return 0.7
	default:
		return 1.0
	}
}

// ValidateDualSource checks that the claim has at least 2 independent source artifacts.
// Fail-closed: returns an error if the dual-source requirement is not met.
func ValidateDualSource(claim KnowledgeClaim) error {
	seen := make(map[string]struct{}, len(claim.SourceArtifactIDs))
	for _, id := range claim.SourceArtifactIDs {
		if id != "" {
			seen[id] = struct{}{}
		}
	}
	if len(seen) < 2 {
		return fmt.Errorf(
			"dual-source validation failed for claim %s: need at least 2 independent sources, got %d",
			claim.ClaimID, len(seen),
		)
	}
	return nil
}

// ComputeClaimHash returns a deterministic SHA-256 content hash for a claim.
// The hash covers: ClaimID, TenantID, StoreClass, Title, Body, sorted SourceArtifactIDs,
// and sorted SourceHashes. Fields that could change due to status transitions are excluded
// so that the hash reflects stable claim content.
func ComputeClaimHash(claim KnowledgeClaim) string {
	sortedArtifacts := make([]string, len(claim.SourceArtifactIDs))
	copy(sortedArtifacts, claim.SourceArtifactIDs)
	sort.Strings(sortedArtifacts)

	sortedHashes := make([]string, len(claim.SourceHashes))
	copy(sortedHashes, claim.SourceHashes)
	sort.Strings(sortedHashes)

	input := strings.Join([]string{
		claim.ClaimID,
		claim.TenantID,
		string(claim.StoreClass),
		claim.Title,
		claim.Body,
		strings.Join(sortedArtifacts, ","),
		strings.Join(sortedHashes, ","),
	}, "|")

	h := sha256.Sum256([]byte(input))
	return "sha256:" + hex.EncodeToString(h[:])
}
