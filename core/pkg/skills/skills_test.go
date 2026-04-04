package skills

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

// --- Test 1: Promotion ladder validation ---

func TestValidTransition(t *testing.T) {
	// Valid forward transitions
	assert.True(t, ValidTransition(PromotionC0Sandbox, PromotionC1Shadow), "C0→C1 should be valid")
	assert.True(t, ValidTransition(PromotionC1Shadow, PromotionC2Canary), "C1→C2 should be valid")
	assert.True(t, ValidTransition(PromotionC2Canary, PromotionC3Production), "C2→C3 should be valid")

	// No skipping
	assert.False(t, ValidTransition(PromotionC0Sandbox, PromotionC2Canary), "C0→C2 should be invalid (skip)")
	assert.False(t, ValidTransition(PromotionC0Sandbox, PromotionC3Production), "C0→C3 should be invalid (skip)")
	assert.False(t, ValidTransition(PromotionC1Shadow, PromotionC3Production), "C1→C3 should be invalid (skip)")

	// Rollback to C0 is always valid (except from C0)
	assert.True(t, ValidTransition(PromotionC1Shadow, PromotionC0Sandbox), "C1→C0 rollback should be valid")
	assert.True(t, ValidTransition(PromotionC2Canary, PromotionC0Sandbox), "C2→C0 rollback should be valid")
	assert.True(t, ValidTransition(PromotionC3Production, PromotionC0Sandbox), "C3→C0 rollback should be valid")

	// C0→C0 is not valid (not a real rollback)
	assert.False(t, ValidTransition(PromotionC0Sandbox, PromotionC0Sandbox), "C0→C0 should be invalid")

	// No backward transitions other than rollback to C0
	assert.False(t, ValidTransition(PromotionC2Canary, PromotionC1Shadow), "C2→C1 should be invalid")
	assert.False(t, ValidTransition(PromotionC3Production, PromotionC2Canary), "C3→C2 should be invalid")

	// Already at max
	assert.False(t, ValidTransition(PromotionC3Production, PromotionC3Production), "C3→C3 should be invalid")
}

// --- Test 2: Manager approval required ---

func TestRequiresManagerApproval(t *testing.T) {
	assert.False(t, RequiresManagerApproval(PromotionC0Sandbox, PromotionC1Shadow), "C0→C1 should NOT require manager approval")
	assert.True(t, RequiresManagerApproval(PromotionC1Shadow, PromotionC2Canary), "C1→C2 SHOULD require manager approval")
	assert.True(t, RequiresManagerApproval(PromotionC2Canary, PromotionC3Production), "C2→C3 SHOULD require manager approval")
}

// --- Test 3: Propose and review flow (approve) ---

func TestProposeAndApproveFlow(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	graph := proofgraph.NewGraph()
	forge := NewForge(store, graph)

	proposal := &SkillProposal{
		ProposalID:  "prop-1",
		Name:        "email-drafter",
		Description: "Drafts email responses",
		Class:       SkillClassChannel,
		AuthorID:    "agent-1",
		Definition:  []byte(`{"template":"hello","steps":["draft","review"]}`),
	}

	// Propose
	err := forge.ProposeSkill(ctx, proposal)
	require.NoError(t, err)
	assert.Equal(t, "PENDING", proposal.Status)
	assert.NotEmpty(t, proposal.ContentHash)

	// Verify proposal is stored
	stored, err := store.GetProposal(ctx, "prop-1")
	require.NoError(t, err)
	assert.Equal(t, "PENDING", stored.Status)

	// Verify INTENT node in ProofGraph
	assert.Equal(t, 1, graph.Len(), "should have 1 ProofGraph node (INTENT)")

	// Approve
	err = forge.ReviewProposal(ctx, "prop-1", "manager-1", "APPROVE", "")
	require.NoError(t, err)

	// Verify skill created at C0
	stored, err = store.GetProposal(ctx, "prop-1")
	require.NoError(t, err)
	assert.Equal(t, "APPROVED", stored.Status)
	assert.NotEmpty(t, stored.SkillID)

	skill, err := store.GetSkill(ctx, stored.SkillID)
	require.NoError(t, err)
	assert.Equal(t, PromotionC0Sandbox, skill.Level)
	assert.Equal(t, "ACTIVE", skill.Status)
	assert.Equal(t, "email-drafter", skill.Name)
	assert.Equal(t, "manager-1", skill.ManagerID)

	// Verify ATTESTATION node in ProofGraph (INTENT + ATTESTATION = 2 nodes)
	assert.Equal(t, 2, graph.Len(), "should have 2 ProofGraph nodes (INTENT + ATTESTATION)")
}

// --- Test 4: Propose and reject flow ---

func TestProposeAndRejectFlow(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	graph := proofgraph.NewGraph()
	forge := NewForge(store, graph)

	proposal := &SkillProposal{
		ProposalID:  "prop-2",
		Name:        "bad-skill",
		Description: "A skill that should be rejected",
		Class:       SkillClassInternal,
		AuthorID:    "agent-2",
		Definition:  []byte(`{"steps":["do-bad-thing"]}`),
	}

	err := forge.ProposeSkill(ctx, proposal)
	require.NoError(t, err)

	// Reject
	err = forge.ReviewProposal(ctx, "prop-2", "manager-1", "REJECT", "too risky")
	require.NoError(t, err)

	stored, err := store.GetProposal(ctx, "prop-2")
	require.NoError(t, err)
	assert.Equal(t, "REJECTED", stored.Status)
	assert.Equal(t, "too risky", stored.RejectReason)

	// No skill should have been created
	skills, err := store.ListSkills(ctx, PromotionC0Sandbox)
	require.NoError(t, err)
	assert.Empty(t, skills, "no skill should exist after rejection")
}

// --- Test 5: Full promotion lifecycle ---

func TestFullPromotionLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	graph := proofgraph.NewGraph()
	forge := NewForge(store, graph)

	// Step 1: Propose and approve a skill
	proposal := &SkillProposal{
		ProposalID:  "prop-lifecycle",
		Name:        "recruiter-screener",
		Description: "Screens job applications",
		Class:       SkillClassActionPack,
		AuthorID:    "agent-recruiter",
		Definition:  []byte(`{"steps":["parse_resume","score","classify"]}`),
	}
	require.NoError(t, forge.ProposeSkill(ctx, proposal))
	require.NoError(t, forge.ReviewProposal(ctx, "prop-lifecycle", "manager-hr", "APPROVE", ""))

	storedProposal, err := store.GetProposal(ctx, "prop-lifecycle")
	require.NoError(t, err)
	skillID := storedProposal.SkillID

	// Verify at C0
	skill, err := store.GetSkill(ctx, skillID)
	require.NoError(t, err)
	assert.Equal(t, PromotionC0Sandbox, skill.Level)

	// Step 2: C0 → C1 (sandbox eval, no manager approval needed)
	err = forge.RequestPromotion(ctx, skillID, "agent-recruiter")
	require.NoError(t, err)

	skill, err = store.GetSkill(ctx, skillID)
	require.NoError(t, err)
	assert.Equal(t, PromotionC1Shadow, skill.Level, "should be at C1 after sandbox eval passes")

	// Step 3: C1 → C2 (canary eval, requires manager approval)
	err = forge.RequestPromotion(ctx, skillID, "agent-recruiter")
	require.NoError(t, err)

	// Skill should still be at C1 — pending manager approval
	skill, err = store.GetSkill(ctx, skillID)
	require.NoError(t, err)
	assert.Equal(t, PromotionC1Shadow, skill.Level, "should still be at C1 pending manager approval")

	// Find the pending promotion request
	pending := findPendingPromotion(t, store, skillID)
	require.NotNil(t, pending, "should have a pending promotion request")

	// Manager approves
	err = forge.ApprovePromotion(ctx, pending.RequestID, "manager-hr")
	require.NoError(t, err)

	skill, err = store.GetSkill(ctx, skillID)
	require.NoError(t, err)
	assert.Equal(t, PromotionC2Canary, skill.Level, "should be at C2 after manager approval")

	// Step 4: C2 → C3 (canary eval, requires manager approval)
	err = forge.RequestPromotion(ctx, skillID, "agent-recruiter")
	require.NoError(t, err)

	pending = findPendingPromotion(t, store, skillID)
	require.NotNil(t, pending)

	err = forge.ApprovePromotion(ctx, pending.RequestID, "manager-hr")
	require.NoError(t, err)

	skill, err = store.GetSkill(ctx, skillID)
	require.NoError(t, err)
	assert.Equal(t, PromotionC3Production, skill.Level, "should be at C3 (production)")
}

// --- Test 6: Rollback from any level ---

func TestRollbackFromAnyLevel(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	graph := proofgraph.NewGraph()
	forge := NewForge(store, graph)

	// Create a skill at C2 directly for testing rollback.
	skill := &Skill{
		SkillID:     "skill-rollback",
		Name:        "test-skill",
		Description: "A skill to test rollback",
		Class:       SkillClassInternal,
		Version:     1,
		Level:       PromotionC2Canary,
		AuthorID:    "agent-1",
		ManagerID:   "manager-1",
		ContentHash: "abc123",
		Status:      "ACTIVE",
	}
	require.NoError(t, store.CreateSkill(ctx, skill))

	// Rollback to C0
	err := forge.RollbackSkill(ctx, "skill-rollback", "manager-1", "performance degradation")
	require.NoError(t, err)

	rolledBack, err := store.GetSkill(ctx, "skill-rollback")
	require.NoError(t, err)
	assert.Equal(t, PromotionC0Sandbox, rolledBack.Level, "skill should be back at C0 after rollback")

	// Verify lineage was recorded
	lineage, err := store.GetLineage(ctx, "skill-rollback")
	require.NoError(t, err)
	require.Len(t, lineage, 1)
	assert.Equal(t, "ROLLED_BACK", lineage[0].Action)
	assert.Equal(t, PromotionC2Canary, lineage[0].FromLevel)
	assert.Equal(t, PromotionC0Sandbox, lineage[0].ToLevel)
}

// --- Test 7: Unauthorized self-promotion (eval failure blocks promotion) ---

func TestEvalFailureBlocksPromotion(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	graph := proofgraph.NewGraph()
	forge := NewForge(store, graph)

	// Use a failing evaluator
	forge.WithEvaluator(NewEvaluator().WithSandboxFunc(
		func(ctx context.Context, skill *Skill) (*EvalResult, error) {
			return &EvalResult{
				EvalID:     "eval-fail",
				SkillID:    skill.SkillID,
				Level:      PromotionC0Sandbox,
				Passed:     false,
				Score:      0.3,
				ErrorCount: 5,
				SampleSize: 100,
			}, nil
		},
	))

	// Create a skill at C0
	skill := &Skill{
		SkillID:     "skill-fail-eval",
		Name:        "flaky-skill",
		Description: "A skill that fails eval",
		Class:       SkillClassInternal,
		Version:     1,
		Level:       PromotionC0Sandbox,
		AuthorID:    "agent-1",
		ManagerID:   "manager-1",
		ContentHash: "def456",
		Status:      "ACTIVE",
	}
	require.NoError(t, store.CreateSkill(ctx, skill))

	// Try to promote — should fail
	err := forge.RequestPromotion(ctx, "skill-fail-eval", "agent-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "evaluation did not pass")

	// Skill should remain at C0
	s, err := store.GetSkill(ctx, "skill-fail-eval")
	require.NoError(t, err)
	assert.Equal(t, PromotionC0Sandbox, s.Level, "skill should remain at C0 when eval fails")
}

// --- Test 8: Suspend and retire ---

func TestSuspendAndRetire(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	graph := proofgraph.NewGraph()
	forge := NewForge(store, graph)

	skill := &Skill{
		SkillID:     "skill-suspend",
		Name:        "suspendable-skill",
		Description: "A skill that will be suspended",
		Class:       SkillClassChannel,
		Version:     1,
		Level:       PromotionC1Shadow,
		AuthorID:    "agent-1",
		ManagerID:   "manager-1",
		ContentHash: "ghi789",
		Status:      "ACTIVE",
	}
	require.NoError(t, store.CreateSkill(ctx, skill))

	// Suspend
	err := forge.SuspendSkill(ctx, "skill-suspend", "manager-1", "security concern")
	require.NoError(t, err)

	s, err := store.GetSkill(ctx, "skill-suspend")
	require.NoError(t, err)
	assert.Equal(t, "SUSPENDED", s.Status)

	// Verify lineage
	lineage, err := store.GetLineage(ctx, "skill-suspend")
	require.NoError(t, err)
	require.Len(t, lineage, 1)
	assert.Equal(t, "SUSPENDED", lineage[0].Action)

	// Now retire a different skill
	retireSkill := &Skill{
		SkillID:     "skill-retire",
		Name:        "old-skill",
		Description: "A skill that will be retired",
		Class:       SkillClassExternalComms,
		Version:     1,
		Level:       PromotionC3Production,
		AuthorID:    "agent-1",
		ManagerID:   "manager-1",
		ContentHash: "jkl012",
		Status:      "ACTIVE",
	}
	require.NoError(t, store.CreateSkill(ctx, retireSkill))

	err = forge.RetireSkill(ctx, "skill-retire", "manager-1")
	require.NoError(t, err)

	s, err = store.GetSkill(ctx, "skill-retire")
	require.NoError(t, err)
	assert.Equal(t, "RETIRED", s.Status)

	lineage, err = store.GetLineage(ctx, "skill-retire")
	require.NoError(t, err)
	require.Len(t, lineage, 1)
	assert.Equal(t, "RETIRED", lineage[0].Action)
}

// --- Test 9: Lineage tracking ---

func TestLineageTracking(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	graph := proofgraph.NewGraph()
	forge := NewForge(store, graph)

	// Full lifecycle: propose → approve → promote C0→C1 → rollback
	proposal := &SkillProposal{
		ProposalID:  "prop-lineage",
		Name:        "lineage-skill",
		Description: "Tracks lineage",
		Class:       SkillClassInternal,
		AuthorID:    "agent-lineage",
		Definition:  []byte(`{"steps":["a","b","c"]}`),
	}
	require.NoError(t, forge.ProposeSkill(ctx, proposal))
	require.NoError(t, forge.ReviewProposal(ctx, "prop-lineage", "manager-lineage", "APPROVE", ""))

	storedProposal, err := store.GetProposal(ctx, "prop-lineage")
	require.NoError(t, err)
	skillID := storedProposal.SkillID

	// Promote C0→C1
	require.NoError(t, forge.RequestPromotion(ctx, skillID, "agent-lineage"))

	// Rollback to C0
	require.NoError(t, forge.RollbackSkill(ctx, skillID, "manager-lineage", "testing"))

	// Check lineage: CREATED + PROMOTED + ROLLED_BACK = 3 entries
	lineage, err := forge.GetLineage(ctx, skillID)
	require.NoError(t, err)
	require.Len(t, lineage, 3, "should have 3 lineage entries")

	assert.Equal(t, "CREATED", lineage[0].Action)
	assert.Equal(t, "PROMOTED", lineage[1].Action)
	assert.Equal(t, PromotionC0Sandbox, lineage[1].FromLevel)
	assert.Equal(t, PromotionC1Shadow, lineage[1].ToLevel)
	assert.Equal(t, "ROLLED_BACK", lineage[2].Action)
	assert.Equal(t, PromotionC1Shadow, lineage[2].FromLevel)
	assert.Equal(t, PromotionC0Sandbox, lineage[2].ToLevel)

	// Every lineage entry should have a ProofGraph node reference
	for i, entry := range lineage {
		assert.NotEmpty(t, entry.ProofGraphNode, "lineage entry %d should have ProofGraph node", i)
		assert.NotEmpty(t, entry.EntryID, "lineage entry %d should have EntryID", i)
	}
}

// --- Test 10: ProofGraph integration ---

func TestProofGraphIntegration(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	graph := proofgraph.NewGraph()
	forge := NewForge(store, graph)

	proposal := &SkillProposal{
		ProposalID:  "prop-proof",
		Name:        "proof-skill",
		Description: "Verifies ProofGraph integration",
		Class:       SkillClassInternal,
		AuthorID:    "agent-proof",
		Definition:  []byte(`{"steps":["verify"]}`),
	}

	// Propose creates INTENT node
	initialLen := graph.Len()
	require.NoError(t, forge.ProposeSkill(ctx, proposal))
	assert.Equal(t, initialLen+1, graph.Len(), "INTENT node should be appended")

	// Verify the INTENT node
	heads := graph.Heads()
	require.Len(t, heads, 1)
	intentNode, ok := graph.Get(heads[0])
	require.True(t, ok)
	assert.Equal(t, proofgraph.NodeTypeIntent, intentNode.Kind)

	// Approve creates ATTESTATION node
	require.NoError(t, forge.ReviewProposal(ctx, "prop-proof", "manager-proof", "APPROVE", ""))
	assert.Equal(t, initialLen+2, graph.Len(), "ATTESTATION node should be appended")

	heads = graph.Heads()
	require.Len(t, heads, 1)
	attestNode, ok := graph.Get(heads[0])
	require.True(t, ok)
	assert.Equal(t, proofgraph.NodeTypeAttestation, attestNode.Kind)

	// Promote creates TRUST_EVENT node
	storedProposal, err := store.GetProposal(ctx, "prop-proof")
	require.NoError(t, err)

	require.NoError(t, forge.RequestPromotion(ctx, storedProposal.SkillID, "agent-proof"))
	assert.Equal(t, initialLen+3, graph.Len(), "TRUST_EVENT node should be appended")

	heads = graph.Heads()
	require.Len(t, heads, 1)
	trustNode, ok := graph.Get(heads[0])
	require.True(t, ok)
	assert.Equal(t, proofgraph.NodeTypeTrustEvent, trustNode.Kind)

	// Validate the entire chain
	err = graph.ValidateChain(heads[0])
	assert.NoError(t, err, "ProofGraph chain should be valid")
}

// --- Test 11: Content hash determinism ---

func TestContentHashDeterminism(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	graph := proofgraph.NewGraph()
	forge := NewForge(store, graph)

	definition := []byte(`{"steps":["alpha","beta","gamma"],"version":1}`)

	proposal1 := &SkillProposal{
		ProposalID:  "prop-hash-1",
		Name:        "hash-test-1",
		Description: "First instance",
		Class:       SkillClassInternal,
		AuthorID:    "agent-1",
		Definition:  definition,
	}
	require.NoError(t, forge.ProposeSkill(ctx, proposal1))

	proposal2 := &SkillProposal{
		ProposalID:  "prop-hash-2",
		Name:        "hash-test-2",
		Description: "Second instance, same definition",
		Class:       SkillClassInternal,
		AuthorID:    "agent-2",
		Definition:  definition,
	}
	require.NoError(t, forge.ProposeSkill(ctx, proposal2))

	assert.Equal(t, proposal1.ContentHash, proposal2.ContentHash,
		"same definition should produce identical content hash")
	assert.NotEmpty(t, proposal1.ContentHash)

	// Verify the hash matches what canonicalize.CanonicalHash produces directly
	expectedHash, err := canonicalize.CanonicalHash(json.RawMessage(definition))
	require.NoError(t, err)
	assert.Equal(t, expectedHash, proposal1.ContentHash)

	// Different definition should produce different hash
	differentDef := []byte(`{"steps":["alpha","beta","delta"],"version":2}`)
	proposal3 := &SkillProposal{
		ProposalID:  "prop-hash-3",
		Name:        "hash-test-3",
		Description: "Different definition",
		Class:       SkillClassInternal,
		AuthorID:    "agent-3",
		Definition:  differentDef,
	}
	require.NoError(t, forge.ProposeSkill(ctx, proposal3))

	assert.NotEqual(t, proposal1.ContentHash, proposal3.ContentHash,
		"different definitions should produce different content hashes")
}

// --- Test 12: Eval failure blocks promotion (sandbox) ---

func TestSandboxEvalFailureBlocksC0ToC1(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	graph := proofgraph.NewGraph()
	forge := NewForge(store, graph)

	// Override evaluator to fail sandbox
	forge.WithEvaluator(NewEvaluator().WithSandboxFunc(
		func(ctx context.Context, skill *Skill) (*EvalResult, error) {
			return &EvalResult{
				EvalID:     "eval-sandbox-fail",
				SkillID:    skill.SkillID,
				Level:      PromotionC0Sandbox,
				Passed:     false,
				Score:      0.2,
				ErrorCount: 10,
				SampleSize: 50,
				Details:    "too many errors in sandbox",
			}, nil
		},
	))

	skill := &Skill{
		SkillID:     "skill-blocked",
		Name:        "blocked-skill",
		Description: "Should not promote",
		Class:       SkillClassInternal,
		Version:     1,
		Level:       PromotionC0Sandbox,
		AuthorID:    "agent-1",
		ManagerID:   "manager-1",
		ContentHash: "blocked123",
		Status:      "ACTIVE",
	}
	require.NoError(t, store.CreateSkill(ctx, skill))

	err := forge.RequestPromotion(ctx, "skill-blocked", "agent-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "evaluation did not pass")
	assert.Contains(t, err.Error(), "0.20")

	// Verify still at C0
	s, err := store.GetSkill(ctx, "skill-blocked")
	require.NoError(t, err)
	assert.Equal(t, PromotionC0Sandbox, s.Level)
}

// --- Additional edge case tests ---

func TestCannotPromoteInactiveSkill(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	graph := proofgraph.NewGraph()
	forge := NewForge(store, graph)

	skill := &Skill{
		SkillID:     "skill-inactive",
		Name:        "inactive-skill",
		Class:       SkillClassInternal,
		Version:     1,
		Level:       PromotionC0Sandbox,
		AuthorID:    "agent-1",
		ContentHash: "inactive123",
		Status:      "SUSPENDED",
	}
	require.NoError(t, store.CreateSkill(ctx, skill))

	err := forge.RequestPromotion(ctx, "skill-inactive", "agent-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not active")
}

func TestCannotPromoteBeyondC3(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	graph := proofgraph.NewGraph()
	forge := NewForge(store, graph)

	skill := &Skill{
		SkillID:     "skill-max",
		Name:        "max-skill",
		Class:       SkillClassInternal,
		Version:     1,
		Level:       PromotionC3Production,
		AuthorID:    "agent-1",
		ContentHash: "max123",
		Status:      "ACTIVE",
	}
	require.NoError(t, store.CreateSkill(ctx, skill))

	err := forge.RequestPromotion(ctx, "skill-max", "agent-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum level")
}

func TestCannotReviewNonPendingProposal(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	graph := proofgraph.NewGraph()
	forge := NewForge(store, graph)

	proposal := &SkillProposal{
		ProposalID:  "prop-double",
		Name:        "double-review",
		Description: "Should not be reviewable twice",
		Class:       SkillClassInternal,
		AuthorID:    "agent-1",
		Definition:  []byte(`{"steps":["once"]}`),
	}
	require.NoError(t, forge.ProposeSkill(ctx, proposal))
	require.NoError(t, forge.ReviewProposal(ctx, "prop-double", "manager-1", "APPROVE", ""))

	// Try to review again
	err := forge.ReviewProposal(ctx, "prop-double", "manager-2", "APPROVE", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not pending")
}

func TestRollbackFromC0Errors(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	graph := proofgraph.NewGraph()
	forge := NewForge(store, graph)

	skill := &Skill{
		SkillID:     "skill-c0",
		Name:        "already-c0",
		Class:       SkillClassInternal,
		Version:     1,
		Level:       PromotionC0Sandbox,
		AuthorID:    "agent-1",
		ContentHash: "c0hash",
		Status:      "ACTIVE",
	}
	require.NoError(t, store.CreateSkill(ctx, skill))

	err := forge.RollbackSkill(ctx, "skill-c0", "manager-1", "no reason")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already at C0_SANDBOX")
}

// helper: find a pending promotion request for a given skill.
func findPendingPromotion(t *testing.T, store *InMemorySkillStore, skillID string) *PromotionRequest {
	t.Helper()
	store.mu.RLock()
	defer store.mu.RUnlock()
	for _, req := range store.promotions {
		if req.SkillID == skillID && req.Status == "PENDING" {
			return req
		}
	}
	return nil
}
