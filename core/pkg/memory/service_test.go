package memory

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestMemStore seeds a MemoryStore with a single LKS entry whose
// EntryID matches claimID, ready for Promote() to operate on.
func newTestMemStore(claimID string) *InMemoryStore {
	ms := NewInMemoryStore()
	_ = ms.Put(MemoryEntry{
		EntryID:     claimID,
		Tier:        TierLKS,
		Namespace:   "test",
		Key:         claimID,
		Value:       "test-value",
		Source:      "test",
		ReviewState: ReviewPending,
		TrustScore:  0.5,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		ContentHash: "sha256:seed",
	})
	return ms
}

// newDualSourceClaim builds a KnowledgeClaim with two independent source artifacts.
func newDualSourceClaim(claimID, tenantID string) KnowledgeClaim {
	return KnowledgeClaim{
		ClaimID:           claimID,
		TenantID:          tenantID,
		StoreClass:        LKS,
		Title:             "Test Claim",
		Body:              "Body text.",
		SourceArtifactIDs: []string{"src-a", "src-b"},
		SourceHashes:      []string{"h1", "h2"},
		ProvenanceScore:   0.7,
		PromotionReq: PromotionRequirement{
			DualSourceRequired: true,
			MinSignerCount:     1,
		},
		Status: "pending",
	}
}

// newSingleSourceClaim builds a claim with only one source artifact.
func newSingleSourceClaim(claimID, tenantID string) KnowledgeClaim {
	c := newDualSourceClaim(claimID, tenantID)
	c.SourceArtifactIDs = []string{"src-only"}
	c.SourceHashes = []string{"h1"}
	c.ProvenanceScore = 0.3
	return c
}

// ---------------------------------------------------------------------------
// WriteLKS tests
// ---------------------------------------------------------------------------

func TestWriteLKS_HappyPath(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	claim := newDualSourceClaim("claim-1", "tenant-a")
	err := svc.WriteLKS(context.Background(), claim)
	require.NoError(t, err)

	got, err := cs.GetClaim(context.Background(), "claim-1")
	require.NoError(t, err)
	assert.Equal(t, LKS, got.StoreClass)
	assert.Equal(t, "pending", got.Status)
	assert.Equal(t, "tenant-a", got.TenantID)
}

func TestWriteLKS_MissingClaimID(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	claim := newDualSourceClaim("", "tenant-a")
	err := svc.WriteLKS(context.Background(), claim)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "claim_id")
}

func TestWriteLKS_MissingTenantID(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	claim := newDualSourceClaim("claim-2", "")
	err := svc.WriteLKS(context.Background(), claim)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id")
}

func TestWriteLKS_NoSourceArtifacts(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	claim := newDualSourceClaim("claim-3", "tenant-a")
	claim.SourceArtifactIDs = nil
	err := svc.WriteLKS(context.Background(), claim)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source artifact")
}

func TestWriteLKS_NegativeProvenanceScore(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	claim := newDualSourceClaim("claim-4", "tenant-a")
	claim.ProvenanceScore = -0.1
	err := svc.WriteLKS(context.Background(), claim)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provenance_score")
}

func TestWriteLKS_MissingTitle(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	claim := newDualSourceClaim("claim-5", "tenant-a")
	claim.Title = ""
	err := svc.WriteLKS(context.Background(), claim)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "title")
}

// ---------------------------------------------------------------------------
// RequestPromotion tests
// ---------------------------------------------------------------------------

func TestRequestPromotion_HappyPath(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	claim := newDualSourceClaim("claim-rp1", "tenant-a")
	require.NoError(t, svc.WriteLKS(context.Background(), claim))

	err := svc.RequestPromotion(context.Background(), "claim-rp1")
	require.NoError(t, err)

	got, err := cs.GetClaim(context.Background(), "claim-rp1")
	require.NoError(t, err)
	assert.Equal(t, "reviewing", got.Status)
}

func TestRequestPromotion_NotPendingFails(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	claim := newDualSourceClaim("claim-rp2", "tenant-a")
	claim.Status = "reviewing"
	require.NoError(t, cs.PutClaim(context.Background(), claim))

	err := svc.RequestPromotion(context.Background(), "claim-rp2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reviewing")
}

func TestRequestPromotion_UnknownClaim(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	err := svc.RequestPromotion(context.Background(), "does-not-exist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// PromoteToCKS tests — dual-source validation
// ---------------------------------------------------------------------------

func TestPromoteToCKS_HappyPath_DualSource(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := newTestMemStore("claim-p1")
	svc, _ := NewDefaultService(cs, ms)

	claim := newDualSourceClaim("claim-p1", "tenant-a")
	require.NoError(t, cs.PutClaim(context.Background(), claim))
	require.NoError(t, cs.UpdateClaimStatus(context.Background(), "claim-p1", "reviewing"))

	err := svc.PromoteToCKS(context.Background(), "claim-p1", "approver-x")
	require.NoError(t, err)

	got, err := cs.GetClaim(context.Background(), "claim-p1")
	require.NoError(t, err)
	assert.Equal(t, "approved", got.Status)
}

func TestPromoteToCKS_DualSourceRequired_OnlyOneSource_Fails(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := newTestMemStore("claim-p2")
	svc, _ := NewDefaultService(cs, ms)

	claim := newSingleSourceClaim("claim-p2", "tenant-a")
	claim.PromotionReq.DualSourceRequired = true
	require.NoError(t, cs.PutClaim(context.Background(), claim))
	require.NoError(t, cs.UpdateClaimStatus(context.Background(), "claim-p2", "reviewing"))

	err := svc.PromoteToCKS(context.Background(), "claim-p2", "approver-x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dual-source")
}

func TestPromoteToCKS_DualSourceNotRequired_SingleSourceAllowed(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := newTestMemStore("claim-p3")
	svc, _ := NewDefaultService(cs, ms)

	claim := newSingleSourceClaim("claim-p3", "tenant-a")
	claim.PromotionReq.DualSourceRequired = false
	require.NoError(t, cs.PutClaim(context.Background(), claim))
	require.NoError(t, cs.UpdateClaimStatus(context.Background(), "claim-p3", "reviewing"))

	err := svc.PromoteToCKS(context.Background(), "claim-p3", "approver-x")
	require.NoError(t, err)
}

func TestPromoteToCKS_WrongStatus_Fails(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := newTestMemStore("claim-p4")
	svc, _ := NewDefaultService(cs, ms)

	claim := newDualSourceClaim("claim-p4", "tenant-a")
	// Status is still "pending", not "reviewing".
	require.NoError(t, cs.PutClaim(context.Background(), claim))

	err := svc.PromoteToCKS(context.Background(), "claim-p4", "approver-x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pending")
}

func TestPromoteToCKS_EmptyApprover_Fails(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := newTestMemStore("claim-p5")
	svc, _ := NewDefaultService(cs, ms)

	claim := newDualSourceClaim("claim-p5", "tenant-a")
	require.NoError(t, cs.PutClaim(context.Background(), claim))
	require.NoError(t, cs.UpdateClaimStatus(context.Background(), "claim-p5", "reviewing"))

	err := svc.PromoteToCKS(context.Background(), "claim-p5", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "approver")
}

func TestPromoteToCKS_NoMemoryEntry_Fails(t *testing.T) {
	cs := NewInMemoryClaimStore()
	// No corresponding MemoryEntry seeded in ms.
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	claim := newDualSourceClaim("claim-p6", "tenant-a")
	require.NoError(t, cs.PutClaim(context.Background(), claim))
	require.NoError(t, cs.UpdateClaimStatus(context.Background(), "claim-p6", "reviewing"))

	err := svc.PromoteToCKS(context.Background(), "claim-p6", "approver-x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "promotion failed")
}

// ---------------------------------------------------------------------------
// RejectPromotion tests
// ---------------------------------------------------------------------------

func TestRejectPromotion_HappyPath(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	claim := newDualSourceClaim("claim-r1", "tenant-a")
	require.NoError(t, cs.PutClaim(context.Background(), claim))

	err := svc.RejectPromotion(context.Background(), "claim-r1", "insufficient evidence")
	require.NoError(t, err)

	got, err := cs.GetClaim(context.Background(), "claim-r1")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(got.Status, "rejected:"))
	assert.Contains(t, got.Status, "insufficient evidence")
}

func TestRejectPromotion_UnknownClaim(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	err := svc.RejectPromotion(context.Background(), "ghost", "no reason needed")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRejectPromotion_EmptyReason_Fails(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	claim := newDualSourceClaim("claim-r2", "tenant-a")
	require.NoError(t, cs.PutClaim(context.Background(), claim))

	err := svc.RejectPromotion(context.Background(), "claim-r2", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reason")
}

// ---------------------------------------------------------------------------
// Query filtering tests
// ---------------------------------------------------------------------------

func TestQuery_FilterByStoreClass(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	lksClaim := newDualSourceClaim("q-lks", "tenant-q")
	cksClaim := newDualSourceClaim("q-cks", "tenant-q")
	cksClaim.StoreClass = CKS

	require.NoError(t, cs.PutClaim(context.Background(), lksClaim))
	require.NoError(t, cs.PutClaim(context.Background(), cksClaim))

	results, err := svc.Query(context.Background(), "tenant-q", Query{StoreClass: LKS})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "q-lks", results[0].ClaimID)
}

func TestQuery_FilterByStatus(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	c1 := newDualSourceClaim("q-s1", "tenant-q")
	c1.Status = "pending"
	c2 := newDualSourceClaim("q-s2", "tenant-q")
	c2.Status = "approved"

	require.NoError(t, cs.PutClaim(context.Background(), c1))
	require.NoError(t, cs.PutClaim(context.Background(), c2))

	results, err := svc.Query(context.Background(), "tenant-q", Query{Status: "approved"})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "q-s2", results[0].ClaimID)
}

func TestQuery_FilterByTitleLike(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	c1 := newDualSourceClaim("q-t1", "tenant-q")
	c1.Title = "Alpha strategy"
	c2 := newDualSourceClaim("q-t2", "tenant-q")
	c2.Title = "Beta approach"

	require.NoError(t, cs.PutClaim(context.Background(), c1))
	require.NoError(t, cs.PutClaim(context.Background(), c2))

	results, err := svc.Query(context.Background(), "tenant-q", Query{TitleLike: "alpha"})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "q-t1", results[0].ClaimID)
}

func TestQuery_LimitApplied(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	for i := range 5 {
		c := newDualSourceClaim("q-lim-"+string(rune('a'+i)), "tenant-q")
		require.NoError(t, cs.PutClaim(context.Background(), c))
	}

	results, err := svc.Query(context.Background(), "tenant-q", Query{Limit: 3})
	require.NoError(t, err)
	assert.LessOrEqual(t, len(results), 3)
}

func TestQuery_EmptyTenantID_Fails(t *testing.T) {
	cs := NewInMemoryClaimStore()
	ms := NewInMemoryStore()
	svc, _ := NewDefaultService(cs, ms)

	_, err := svc.Query(context.Background(), "", Query{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id")
}

// ---------------------------------------------------------------------------
// Provenance scoring tests
// ---------------------------------------------------------------------------

func TestScoreProvenance_ZeroSources(t *testing.T) {
	c := KnowledgeClaim{}
	assert.Equal(t, 0.0, ScoreProvenance(c))
}

func TestScoreProvenance_OneSource(t *testing.T) {
	c := KnowledgeClaim{SourceArtifactIDs: []string{"src-a"}}
	assert.Equal(t, 0.3, ScoreProvenance(c))
}

func TestScoreProvenance_TwoSources(t *testing.T) {
	c := KnowledgeClaim{SourceArtifactIDs: []string{"src-a", "src-b"}}
	assert.Equal(t, 0.7, ScoreProvenance(c))
}

func TestScoreProvenance_ThreeOrMoreSources(t *testing.T) {
	c := KnowledgeClaim{SourceArtifactIDs: []string{"src-a", "src-b", "src-c"}}
	assert.Equal(t, 1.0, ScoreProvenance(c))
}

func TestScoreProvenance_DuplicatesCounted_Once(t *testing.T) {
	// Two entries but same ID → treated as 1 unique source.
	c := KnowledgeClaim{SourceArtifactIDs: []string{"src-a", "src-a"}}
	assert.Equal(t, 0.3, ScoreProvenance(c))
}

// ---------------------------------------------------------------------------
// ComputeClaimHash tests
// ---------------------------------------------------------------------------

func TestComputeClaimHash_Deterministic(t *testing.T) {
	c := newDualSourceClaim("hash-1", "tenant-h")
	h1 := ComputeClaimHash(c)
	h2 := ComputeClaimHash(c)
	assert.Equal(t, h1, h2)
	assert.True(t, strings.HasPrefix(h1, "sha256:"))
}

func TestComputeClaimHash_ChangesOnTitleChange(t *testing.T) {
	c := newDualSourceClaim("hash-2", "tenant-h")
	h1 := ComputeClaimHash(c)
	c.Title = "Different title"
	h2 := ComputeClaimHash(c)
	assert.NotEqual(t, h1, h2)
}

func TestComputeClaimHash_SourceOrderIndependent(t *testing.T) {
	c1 := newDualSourceClaim("hash-3", "tenant-h")
	c1.SourceArtifactIDs = []string{"src-a", "src-b"}
	c2 := newDualSourceClaim("hash-3", "tenant-h")
	c2.SourceArtifactIDs = []string{"src-b", "src-a"}
	assert.Equal(t, ComputeClaimHash(c1), ComputeClaimHash(c2))
}

// ---------------------------------------------------------------------------
// ValidateDualSource tests
// ---------------------------------------------------------------------------

func TestValidateDualSource_Passes(t *testing.T) {
	c := newDualSourceClaim("ds-1", "tenant-a")
	assert.NoError(t, ValidateDualSource(c))
}

func TestValidateDualSource_Fails_OneSource(t *testing.T) {
	c := newSingleSourceClaim("ds-2", "tenant-a")
	err := ValidateDualSource(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dual-source")
}

func TestValidateDualSource_Fails_NoSources(t *testing.T) {
	c := KnowledgeClaim{ClaimID: "ds-3"}
	err := ValidateDualSource(c)
	require.Error(t, err)
}

func TestValidateDualSource_Fails_DuplicateSources(t *testing.T) {
	c := KnowledgeClaim{
		ClaimID:           "ds-4",
		SourceArtifactIDs: []string{"src-a", "src-a"},
	}
	err := ValidateDualSource(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dual-source")
}

// ---------------------------------------------------------------------------
// QueryCKS helper tests
// ---------------------------------------------------------------------------

func TestQueryCKS_ForcesStoreClassCKS(t *testing.T) {
	cs := NewInMemoryClaimStore()

	lksClaim := newDualSourceClaim("cks-q1", "tenant-c")
	lksClaim.StoreClass = LKS
	cksClaim := newDualSourceClaim("cks-q2", "tenant-c")
	cksClaim.StoreClass = CKS

	require.NoError(t, cs.PutClaim(context.Background(), lksClaim))
	require.NoError(t, cs.PutClaim(context.Background(), cksClaim))

	// Even if the caller passes StoreClass: LKS, QueryCKS overrides it.
	results, err := QueryCKS(context.Background(), cs, "tenant-c", Query{StoreClass: LKS})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "cks-q2", results[0].ClaimID)
}

func TestQueryCKS_EmptyTenantID_Fails(t *testing.T) {
	cs := NewInMemoryClaimStore()
	_, err := QueryCKS(context.Background(), cs, "", Query{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id")
}

// ---------------------------------------------------------------------------
// WriteLKSClaim helper tests (standalone, bypassing Service)
// ---------------------------------------------------------------------------

func TestWriteLKSClaim_ForcesLKSStoreClass(t *testing.T) {
	cs := NewInMemoryClaimStore()
	claim := newDualSourceClaim("wlks-1", "tenant-w")
	claim.StoreClass = CKS // caller sets wrong class

	require.NoError(t, WriteLKSClaim(context.Background(), cs, claim))

	got, err := cs.GetClaim(context.Background(), "wlks-1")
	require.NoError(t, err)
	assert.Equal(t, LKS, got.StoreClass)
}
