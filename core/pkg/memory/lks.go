// Package memory — LKS-specific write logic.
//
// Per HELM 2030 Spec §5.4:
//
//	LKS MAY influence plan generation. LKS MUST NOT authorize side effects.
//
// Resolves: GAP-A5.
package memory

import (
	"context"
	"fmt"
)

// WriteLKSClaim writes a claim to the Learned Knowledge Store.
// Validates: claim must have at least 1 source artifact, provenance score >= 0,
// and the claim must target the LKS store class.
//
// Fail-closed: any validation failure prevents the write.
func WriteLKSClaim(ctx context.Context, store ClaimStore, claim KnowledgeClaim) error {
	if claim.ClaimID == "" {
		return fmt.Errorf("lks write: claim_id is required")
	}
	if claim.TenantID == "" {
		return fmt.Errorf("lks write: tenant_id is required")
	}
	if claim.Title == "" {
		return fmt.Errorf("lks write: title is required")
	}
	if len(claim.SourceArtifactIDs) == 0 {
		return fmt.Errorf("lks write: claim %s must have at least 1 source artifact", claim.ClaimID)
	}

	// Validate provenance score range.
	if claim.ProvenanceScore < 0 {
		return fmt.Errorf("lks write: provenance_score must be >= 0, got %f", claim.ProvenanceScore)
	}

	// Force store class and status for LKS writes.
	claim.StoreClass = LKS
	if claim.Status == "" {
		claim.Status = "pending"
	}

	if err := store.PutClaim(ctx, claim); err != nil {
		return fmt.Errorf("lks write: store failed for claim %s: %w", claim.ClaimID, err)
	}
	return nil
}
