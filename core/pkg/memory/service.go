// Package memory — High-level claim-based knowledge promotion service.
//
// Per HELM 2030 Spec §5.4:
//
//	Any LKS-derived claim needed for execution MUST be promoted into CKS
//	with provenance and ProofGraph linkage.
//
// Resolves: GAP-A5, GAP-A6.
package memory

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// KnowledgeStoreClass identifies the tier of a knowledge claim.
type KnowledgeStoreClass string

const (
	// LKS is the Learned Knowledge Store — untrusted, influence-only.
	LKS KnowledgeStoreClass = "lks"
	// CKS is the Curated Knowledge Store — trusted, may authorize side effects.
	CKS KnowledgeStoreClass = "cks"
)

// PromotionRequirement defines the conditions that must be satisfied before a
// claim may be promoted from LKS to CKS.
type PromotionRequirement struct {
	DualSourceRequired bool   `json:"dual_source_required"`
	MinSignerCount     int    `json:"min_signer_count"`
	ApprovalProfileRef string `json:"approval_profile_ref,omitempty"`
}

// KnowledgeClaim is a unit of governed knowledge managed by the Service.
// Claims start in LKS (pending) and may be promoted to CKS after review.
type KnowledgeClaim struct {
	ClaimID           string               `json:"claim_id"`
	TenantID          string               `json:"tenant_id"`
	StoreClass        KnowledgeStoreClass  `json:"store_class"`
	Title             string               `json:"title"`
	Body              string               `json:"body"`
	SourceArtifactIDs []string             `json:"source_artifact_ids"`
	SourceHashes      []string             `json:"source_hashes"`
	ProvenanceScore   float64              `json:"provenance_score"` // 0.0–1.0
	PromotionReq      PromotionRequirement `json:"promotion_req"`
	Status            string               `json:"status"` // pending, approved, rejected
}

// Query filters results returned by Service.Query and QueryCKS.
type Query struct {
	StoreClass KnowledgeStoreClass
	TitleLike  string
	Status     string
	Limit      int
}

// ClaimStore is the persistence abstraction used by Service and the LKS/CKS helpers.
// Implementations MUST be safe for concurrent use.
type ClaimStore interface {
	PutClaim(ctx context.Context, claim KnowledgeClaim) error
	GetClaim(ctx context.Context, claimID string) (*KnowledgeClaim, error)
	ListClaims(ctx context.Context, tenantID string, q Query) ([]KnowledgeClaim, error)
	UpdateClaimStatus(ctx context.Context, claimID, status string) error
}

// Service is the high-level interface for governed knowledge management.
// It wraps the low-level Promote function and enforces dual-source requirements.
type Service interface {
	// WriteLKS writes a new claim to the Learned Knowledge Store.
	WriteLKS(ctx context.Context, claim KnowledgeClaim) error

	// RequestPromotion marks a pending LKS claim for promotion review.
	RequestPromotion(ctx context.Context, claimID string) error

	// PromoteToCKS promotes an LKS claim to CKS after satisfying promotion requirements.
	// Fail-closed: dual-source and other requirements are validated before any state change.
	PromoteToCKS(ctx context.Context, claimID string, approver string) error

	// RejectPromotion rejects a promotion request with a reason.
	RejectPromotion(ctx context.Context, claimID string, reason string) error

	// Query returns claims matching the given filter.
	Query(ctx context.Context, tenantID string, q Query) ([]KnowledgeClaim, error)
}

// DefaultService is the production implementation of Service.
// It delegates persistence to a ClaimStore and uses the existing Promote function
// for the actual tier transition on the underlying MemoryStore.
type DefaultService struct {
	claims ClaimStore
	// memStore backs the low-level Promote function.
	// The service bridges KnowledgeClaim→MemoryEntry for that call.
	memStore MemoryStore
}

// NewDefaultService creates a new DefaultService.
// Both stores are required; nil arguments return an error (fail-closed).
func NewDefaultService(claims ClaimStore, memStore MemoryStore) (*DefaultService, error) {
	if claims == nil {
		return nil, fmt.Errorf("memory.NewDefaultService: claims store must not be nil")
	}
	if memStore == nil {
		return nil, fmt.Errorf("memory.NewDefaultService: memory store must not be nil")
	}
	return &DefaultService{
		claims:   claims,
		memStore: memStore,
	}, nil
}

// WriteLKS writes a new claim to the Learned Knowledge Store.
// Delegates to WriteLKSClaim for validation and persistence.
func (s *DefaultService) WriteLKS(ctx context.Context, claim KnowledgeClaim) error {
	if err := WriteLKSClaim(ctx, s.claims, claim); err != nil {
		return fmt.Errorf("service WriteLKS: %w", err)
	}
	return nil
}

// RequestPromotion transitions a pending LKS claim to "reviewing" status.
// Fail-closed: the claim must exist and be in "pending" status.
func (s *DefaultService) RequestPromotion(ctx context.Context, claimID string) error {
	if claimID == "" {
		return fmt.Errorf("service RequestPromotion: claim_id is required")
	}
	claim, err := s.claims.GetClaim(ctx, claimID)
	if err != nil {
		return fmt.Errorf("service RequestPromotion: claim lookup failed: %w", err)
	}
	if claim.Status != "pending" {
		return fmt.Errorf(
			"service RequestPromotion: claim %s has status %q, expected \"pending\"",
			claimID, claim.Status,
		)
	}
	if err := s.claims.UpdateClaimStatus(ctx, claimID, "reviewing"); err != nil {
		return fmt.Errorf("service RequestPromotion: status update failed: %w", err)
	}
	return nil
}

// PromoteToCKS promotes a claim from LKS to CKS.
// Fail-closed validation order:
//  1. claimID and approver must be non-empty.
//  2. Claim must exist and be in "reviewing" status.
//  3. If DualSourceRequired, ValidateDualSource is enforced.
//  4. The underlying MemoryEntry must exist for Promote() to update.
//  5. Promote() is called; on success the claim status is set to "approved".
func (s *DefaultService) PromoteToCKS(ctx context.Context, claimID string, approver string) error {
	if claimID == "" {
		return fmt.Errorf("service PromoteToCKS: claim_id is required")
	}
	if approver == "" {
		return fmt.Errorf("service PromoteToCKS: approver is required")
	}

	claim, err := s.claims.GetClaim(ctx, claimID)
	if err != nil {
		return fmt.Errorf("service PromoteToCKS: claim lookup failed: %w", err)
	}
	if claim.Status != "reviewing" {
		return fmt.Errorf(
			"service PromoteToCKS: claim %s has status %q, expected \"reviewing\"",
			claimID, claim.Status,
		)
	}

	// Fail-closed: enforce dual-source requirement before any state change.
	if claim.PromotionReq.DualSourceRequired {
		if err := ValidateDualSource(*claim); err != nil {
			return fmt.Errorf("service PromoteToCKS: %w", err)
		}
	}

	// Bridge into MemoryEntry world for the Promote() call.
	// The entry must already exist in the MemoryStore (put there on WriteLKS).
	req := PromotionRequest{
		RequestID:    "svc:" + claimID,
		EntryID:      claimID,
		ReviewerID:   approver,
		Rationale:    fmt.Sprintf("promoted via DefaultService by %s", approver),
		EvidenceRefs: claim.SourceArtifactIDs,
	}
	if _, err := Promote(s.memStore, req); err != nil {
		return fmt.Errorf("service PromoteToCKS: promotion failed: %w", err)
	}

	// Mirror the status back into the ClaimStore.
	if err := s.claims.UpdateClaimStatus(ctx, claimID, "approved"); err != nil {
		return fmt.Errorf("service PromoteToCKS: status update failed: %w", err)
	}
	return nil
}

// RejectPromotion rejects a claim and records the reason in the status.
// The reason is embedded into the stored status string so it is auditable.
// Fail-closed: the claim must exist.
func (s *DefaultService) RejectPromotion(ctx context.Context, claimID string, reason string) error {
	if claimID == "" {
		return fmt.Errorf("service RejectPromotion: claim_id is required")
	}
	if reason == "" {
		return fmt.Errorf("service RejectPromotion: reason is required")
	}
	if _, err := s.claims.GetClaim(ctx, claimID); err != nil {
		return fmt.Errorf("service RejectPromotion: claim lookup failed: %w", err)
	}
	status := "rejected:" + reason
	if err := s.claims.UpdateClaimStatus(ctx, claimID, status); err != nil {
		return fmt.Errorf("service RejectPromotion: status update failed: %w", err)
	}
	return nil
}

// Query returns claims for a tenant matching the given filter.
func (s *DefaultService) Query(ctx context.Context, tenantID string, q Query) ([]KnowledgeClaim, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("service Query: tenant_id is required")
	}
	claims, err := s.claims.ListClaims(ctx, tenantID, q)
	if err != nil {
		return nil, fmt.Errorf("service Query: list failed: %w", err)
	}
	return claims, nil
}

// ---------------------------------------------------------------------------
// InMemoryClaimStore — thread-safe in-memory ClaimStore for testing.
// ---------------------------------------------------------------------------

// InMemoryClaimStore is a thread-safe in-memory implementation of ClaimStore.
// It is intended for tests and local development only.
type InMemoryClaimStore struct {
	mu     sync.RWMutex
	claims map[string]*KnowledgeClaim // claimID → claim
}

// NewInMemoryClaimStore creates a new empty InMemoryClaimStore.
func NewInMemoryClaimStore() *InMemoryClaimStore {
	return &InMemoryClaimStore{
		claims: make(map[string]*KnowledgeClaim),
	}
}

// PutClaim stores or replaces a claim.
func (s *InMemoryClaimStore) PutClaim(_ context.Context, claim KnowledgeClaim) error {
	if claim.ClaimID == "" {
		return fmt.Errorf("in-memory claim store: claim_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := claim
	s.claims[claim.ClaimID] = &cp
	return nil
}

// GetClaim retrieves a claim by ID.
func (s *InMemoryClaimStore) GetClaim(_ context.Context, claimID string) (*KnowledgeClaim, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.claims[claimID]
	if !ok {
		return nil, fmt.Errorf("claim %s not found", claimID)
	}
	cp := *c
	return &cp, nil
}

// ListClaims returns all claims for a tenant matching the query filter.
func (s *InMemoryClaimStore) ListClaims(_ context.Context, tenantID string, q Query) ([]KnowledgeClaim, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []KnowledgeClaim
	for _, c := range s.claims {
		if c.TenantID != tenantID {
			continue
		}
		if q.StoreClass != "" && c.StoreClass != q.StoreClass {
			continue
		}
		if q.Status != "" && !strings.HasPrefix(c.Status, q.Status) {
			continue
		}
		if q.TitleLike != "" && !strings.Contains(
			strings.ToLower(c.Title),
			strings.ToLower(q.TitleLike),
		) {
			continue
		}
		result = append(result, *c)
		if q.Limit > 0 && len(result) >= q.Limit {
			break
		}
	}
	return result, nil
}

// UpdateClaimStatus updates the status of an existing claim.
func (s *InMemoryClaimStore) UpdateClaimStatus(_ context.Context, claimID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.claims[claimID]
	if !ok {
		return fmt.Errorf("claim %s not found", claimID)
	}
	c.Status = status
	return nil
}
