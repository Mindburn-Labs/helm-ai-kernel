// Package memory — CKS-specific read/query logic.
//
// Per HELM 2030 Spec §5.4:
//
//	CKS is the Curated Knowledge Store — trusted, may authorize.
//	Only promoted, approved claims reside here.
//
// Resolves: GAP-A5.
package memory

import (
	"context"
	"fmt"
)

// QueryCKS returns claims from the Curated Knowledge Store for a given tenant.
// The query is scoped to CKS regardless of the StoreClass field in q — callers
// must not rely on q.StoreClass to switch to LKS.
//
// Fail-closed: an empty tenantID is rejected.
func QueryCKS(ctx context.Context, store ClaimStore, tenantID string, q Query) ([]KnowledgeClaim, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("cks query: tenant_id is required")
	}

	// Force the store class to CKS regardless of what the caller passes.
	q.StoreClass = CKS

	claims, err := store.ListClaims(ctx, tenantID, q)
	if err != nil {
		return nil, fmt.Errorf("cks query: list failed for tenant %s: %w", tenantID, err)
	}
	return claims, nil
}
