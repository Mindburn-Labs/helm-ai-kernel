package skills

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

// Forge is the governed skill evolution orchestrator.
// It is the ONLY valid entry point for skill creation, modification, and promotion.
type Forge struct {
	store  SkillStore
	ladder *PromotionLadder
	eval   *Evaluator
	graph  *proofgraph.Graph
}

// NewForge creates a new Forge with default evaluator.
func NewForge(store SkillStore, graph *proofgraph.Graph) *Forge {
	return &Forge{
		store:  store,
		ladder: NewPromotionLadder(store, graph),
		eval:   NewEvaluator(),
		graph:  graph,
	}
}

// WithEvaluator sets a custom evaluator (useful for testing).
func (f *Forge) WithEvaluator(eval *Evaluator) *Forge {
	f.eval = eval
	return f
}

// ProposeSkill creates a new skill proposal. The proposal must be reviewed
// before the skill enters the promotion ladder.
// - Computes content hash via canonicalize.CanonicalHash
// - Stores proposal
// - Creates ProofGraph INTENT node
func (f *Forge) ProposeSkill(ctx context.Context, proposal *SkillProposal) error {
	if proposal.ProposalID == "" {
		proposal.ProposalID = uuid.New().String()
	}

	// Compute content hash from the definition.
	hash, err := canonicalize.CanonicalHash(json.RawMessage(proposal.Definition))
	if err != nil {
		return fmt.Errorf("failed to compute content hash: %w", err)
	}
	proposal.ContentHash = hash
	proposal.Status = "PENDING"
	proposal.CreatedAt = time.Now()

	// Store the proposal.
	if err := f.store.CreateProposal(ctx, proposal); err != nil {
		return fmt.Errorf("failed to store proposal: %w", err)
	}

	// Create ProofGraph INTENT node.
	payload, err := json.Marshal(map[string]interface{}{
		"action":       "SKILL_PROPOSED",
		"proposal_id":  proposal.ProposalID,
		"name":         proposal.Name,
		"author_id":    proposal.AuthorID,
		"content_hash": proposal.ContentHash,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal proof payload: %w", err)
	}

	if _, err := f.graph.Append(proofgraph.NodeTypeIntent, payload, proposal.AuthorID, 0); err != nil {
		return fmt.Errorf("failed to append proof graph node: %w", err)
	}

	return nil
}

// ReviewProposal approves or rejects a skill proposal.
// Only managers can review. Approved proposals create a new skill at C0_SANDBOX.
// - decision: "APPROVE" or "REJECT"
// - If approved: creates Skill at C0_SANDBOX, appends lineage entry
// - Creates ProofGraph ATTESTATION node
func (f *Forge) ReviewProposal(ctx context.Context, proposalID, reviewerID, decision, reason string) error {
	proposal, err := f.store.GetProposal(ctx, proposalID)
	if err != nil {
		return fmt.Errorf("failed to get proposal: %w", err)
	}

	if proposal.Status != "PENDING" {
		return fmt.Errorf("proposal %s is not pending (status: %s)", proposalID, proposal.Status)
	}

	now := time.Now()
	proposal.ReviewedAt = &now
	proposal.ReviewedBy = reviewerID

	switch decision {
	case "APPROVE":
		proposal.Status = "APPROVED"

		// Create the skill at C0_SANDBOX.
		skillID := proposal.SkillID
		if skillID == "" {
			skillID = uuid.New().String()
		}

		skill := &Skill{
			SkillID:     skillID,
			Name:        proposal.Name,
			Description: proposal.Description,
			Class:       proposal.Class,
			Version:     1,
			Level:       PromotionC0Sandbox,
			AuthorID:    proposal.AuthorID,
			ManagerID:   reviewerID,
			ContentHash: proposal.ContentHash,
			CreatedAt:   now,
			Status:      "ACTIVE",
		}

		if err := f.store.CreateSkill(ctx, skill); err != nil {
			return fmt.Errorf("failed to create skill: %w", err)
		}

		// Update the proposal with the skill ID (for new skills).
		proposal.SkillID = skillID

		// Create ProofGraph ATTESTATION node.
		payload, err := json.Marshal(map[string]interface{}{
			"action":       "SKILL_APPROVED",
			"proposal_id":  proposalID,
			"skill_id":     skillID,
			"reviewer_id":  reviewerID,
			"content_hash": proposal.ContentHash,
		})
		if err != nil {
			return fmt.Errorf("failed to marshal proof payload: %w", err)
		}

		node, err := f.graph.Append(proofgraph.NodeTypeAttestation, payload, reviewerID, 0)
		if err != nil {
			return fmt.Errorf("failed to append proof graph node: %w", err)
		}

		// Append lineage entry.
		lineageEntry := &SkillLineageEntry{
			EntryID:        uuid.New().String(),
			SkillID:        skillID,
			Version:        1,
			Action:         "CREATED",
			ToLevel:        PromotionC0Sandbox,
			ActorID:        reviewerID,
			ContentHash:    proposal.ContentHash,
			ProofGraphNode: node.NodeHash,
			Timestamp:      now,
		}
		if err := f.store.AppendLineage(ctx, lineageEntry); err != nil {
			return fmt.Errorf("failed to append lineage: %w", err)
		}

	case "REJECT":
		proposal.Status = "REJECTED"
		proposal.RejectReason = reason

		// Create ProofGraph ATTESTATION node for rejection.
		payload, err := json.Marshal(map[string]interface{}{
			"action":      "SKILL_REJECTED",
			"proposal_id": proposalID,
			"reviewer_id": reviewerID,
			"reason":      reason,
		})
		if err != nil {
			return fmt.Errorf("failed to marshal proof payload: %w", err)
		}

		if _, err := f.graph.Append(proofgraph.NodeTypeAttestation, payload, reviewerID, 0); err != nil {
			return fmt.Errorf("failed to append proof graph node: %w", err)
		}

	default:
		return fmt.Errorf("invalid decision: %s (must be APPROVE or REJECT)", decision)
	}

	return nil
}

// RequestPromotion requests promotion of a skill to the next level.
// Automatically runs evaluation for the target level.
// - Validates current level and next valid level
// - Runs appropriate eval (sandbox for C0->C1, canary for C1->C2 and C2->C3)
// - If eval passes and no manager approval needed: auto-promote
// - If eval passes and manager approval needed: create pending promotion request
// - Creates ProofGraph TRUST_EVENT node
func (f *Forge) RequestPromotion(ctx context.Context, skillID, requestedBy string) error {
	skill, err := f.store.GetSkill(ctx, skillID)
	if err != nil {
		return fmt.Errorf("failed to get skill: %w", err)
	}

	if skill.Status != "ACTIVE" {
		return fmt.Errorf("skill %s is not active (status: %s)", skillID, skill.Status)
	}

	target := nextLevel(skill.Level)
	if target == "" {
		return fmt.Errorf("skill %s is already at maximum level %s", skillID, skill.Level)
	}

	// Run appropriate evaluation.
	var evalResult *EvalResult
	switch skill.Level {
	case PromotionC0Sandbox:
		evalResult, err = f.eval.EvalSandbox(ctx, skill)
	case PromotionC1Shadow, PromotionC2Canary:
		evalResult, err = f.eval.EvalCanary(ctx, skill, 100)
	default:
		return fmt.Errorf("unexpected skill level: %s", skill.Level)
	}
	if err != nil {
		return fmt.Errorf("evaluation failed: %w", err)
	}

	req := &PromotionRequest{
		RequestID:   uuid.New().String(),
		SkillID:     skillID,
		FromLevel:   skill.Level,
		ToLevel:     target,
		RequestedBy: requestedBy,
		EvalResult:  evalResult,
		CreatedAt:   time.Now(),
	}

	if !evalResult.Passed {
		req.Status = "REJECTED"
		now := time.Now()
		req.ResolvedAt = &now
		if err := f.store.CreatePromotionRequest(ctx, req); err != nil {
			return fmt.Errorf("failed to store promotion request: %w", err)
		}
		return fmt.Errorf("evaluation did not pass (score: %.2f, errors: %d)", evalResult.Score, evalResult.ErrorCount)
	}

	// Check if manager approval is required.
	if RequiresManagerApproval(skill.Level, target) {
		req.Status = "PENDING"
		if err := f.store.CreatePromotionRequest(ctx, req); err != nil {
			return fmt.Errorf("failed to store promotion request: %w", err)
		}
		return nil // Pending manager approval
	}

	// Auto-promote (no manager approval needed).
	if err := f.ladder.Promote(ctx, req); err != nil {
		return fmt.Errorf("promotion failed: %w", err)
	}

	req.Status = "APPROVED"
	if err := f.store.CreatePromotionRequest(ctx, req); err != nil {
		return fmt.Errorf("failed to store promotion request: %w", err)
	}

	return nil
}

// ApprovePromotion approves a pending promotion request (manager action).
func (f *Forge) ApprovePromotion(ctx context.Context, requestID, approverID string) error {
	req, err := f.store.GetPromotionRequest(ctx, requestID)
	if err != nil {
		return fmt.Errorf("failed to get promotion request: %w", err)
	}

	if req.Status != "PENDING" {
		return fmt.Errorf("promotion request %s is not pending (status: %s)", requestID, req.Status)
	}

	req.ApprovedBy = approverID

	if err := f.ladder.Promote(ctx, req); err != nil {
		return fmt.Errorf("promotion failed: %w", err)
	}

	if err := f.store.UpdatePromotionStatus(ctx, requestID, "APPROVED"); err != nil {
		return fmt.Errorf("failed to update promotion status: %w", err)
	}

	return nil
}

// RollbackSkill demotes a skill back to C0_SANDBOX.
func (f *Forge) RollbackSkill(ctx context.Context, skillID, actorID, reason string) error {
	return f.ladder.Rollback(ctx, skillID, actorID, reason)
}

// SuspendSkill suspends a skill (prevents execution at any level).
func (f *Forge) SuspendSkill(ctx context.Context, skillID, actorID, reason string) error {
	skill, err := f.store.GetSkill(ctx, skillID)
	if err != nil {
		return fmt.Errorf("failed to get skill: %w", err)
	}

	if err := f.store.UpdateSkillStatus(ctx, skillID, "SUSPENDED"); err != nil {
		return fmt.Errorf("failed to suspend skill: %w", err)
	}

	payload, err := json.Marshal(map[string]interface{}{
		"action":   "SUSPENDED",
		"skill_id": skillID,
		"actor":    actorID,
		"reason":   reason,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal proof payload: %w", err)
	}

	node, err := f.graph.Append(proofgraph.NodeTypeTrustEvent, payload, actorID, 0)
	if err != nil {
		return fmt.Errorf("failed to append proof graph node: %w", err)
	}

	lineageEntry := &SkillLineageEntry{
		EntryID:        uuid.New().String(),
		SkillID:        skillID,
		Version:        skill.Version,
		Action:         "SUSPENDED",
		FromLevel:      skill.Level,
		ActorID:        actorID,
		ContentHash:    skill.ContentHash,
		ProofGraphNode: node.NodeHash,
		Timestamp:      time.Now(),
	}
	return f.store.AppendLineage(ctx, lineageEntry)
}

// RetireSkill permanently retires a skill.
func (f *Forge) RetireSkill(ctx context.Context, skillID, actorID string) error {
	skill, err := f.store.GetSkill(ctx, skillID)
	if err != nil {
		return fmt.Errorf("failed to get skill: %w", err)
	}

	if err := f.store.UpdateSkillStatus(ctx, skillID, "RETIRED"); err != nil {
		return fmt.Errorf("failed to retire skill: %w", err)
	}

	payload, err := json.Marshal(map[string]interface{}{
		"action":   "RETIRED",
		"skill_id": skillID,
		"actor":    actorID,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal proof payload: %w", err)
	}

	node, err := f.graph.Append(proofgraph.NodeTypeTrustEvent, payload, actorID, 0)
	if err != nil {
		return fmt.Errorf("failed to append proof graph node: %w", err)
	}

	lineageEntry := &SkillLineageEntry{
		EntryID:        uuid.New().String(),
		SkillID:        skillID,
		Version:        skill.Version,
		Action:         "RETIRED",
		FromLevel:      skill.Level,
		ActorID:        actorID,
		ContentHash:    skill.ContentHash,
		ProofGraphNode: node.NodeHash,
		Timestamp:      time.Now(),
	}
	return f.store.AppendLineage(ctx, lineageEntry)
}

// GetLineage returns the complete history of a skill.
func (f *Forge) GetLineage(ctx context.Context, skillID string) ([]*SkillLineageEntry, error) {
	return f.store.GetLineage(ctx, skillID)
}
