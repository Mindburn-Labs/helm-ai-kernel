package skills

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

// PromotionLadder enforces the skill promotion lifecycle.
type PromotionLadder struct {
	store SkillStore
	graph *proofgraph.Graph
}

// NewPromotionLadder creates a new PromotionLadder.
func NewPromotionLadder(store SkillStore, graph *proofgraph.Graph) *PromotionLadder {
	return &PromotionLadder{
		store: store,
		graph: graph,
	}
}

// promotionOrder defines the sequential promotion path.
var promotionOrder = []PromotionLevel{
	PromotionC0Sandbox,
	PromotionC1Shadow,
	PromotionC2Canary,
	PromotionC3Production,
}

// nextLevel returns the next level in the promotion ladder, or empty if at top.
func nextLevel(current PromotionLevel) PromotionLevel {
	for i, lvl := range promotionOrder {
		if lvl == current && i+1 < len(promotionOrder) {
			return promotionOrder[i+1]
		}
	}
	return ""
}

// ValidTransition checks if a level transition is valid.
// Valid forward transitions: C0->C1, C1->C2, C2->C3. No skipping.
// Rollback: any level -> C0.
func ValidTransition(from, to PromotionLevel) bool {
	// Rollback to C0 is always valid (except from C0 itself).
	if to == PromotionC0Sandbox && from != PromotionC0Sandbox {
		return true
	}
	// Forward: must be exactly the next step.
	return nextLevel(from) == to && to != ""
}

// RequiresManagerApproval returns true if the transition needs manager sign-off.
// C1->C2 and C2->C3 require manager approval.
func RequiresManagerApproval(from, to PromotionLevel) bool {
	if from == PromotionC1Shadow && to == PromotionC2Canary {
		return true
	}
	if from == PromotionC2Canary && to == PromotionC3Production {
		return true
	}
	return false
}

// Promote attempts to promote a skill. Returns error if:
// - transition is invalid
// - manager approval required but not provided
// - eval not passed (for C0->C1 and C1->C2)
// Creates ProofGraph TRUST_EVENT node on success.
func (l *PromotionLadder) Promote(ctx context.Context, req *PromotionRequest) error {
	if !ValidTransition(req.FromLevel, req.ToLevel) {
		return fmt.Errorf("invalid transition from %s to %s", req.FromLevel, req.ToLevel)
	}

	if RequiresManagerApproval(req.FromLevel, req.ToLevel) && req.ApprovedBy == "" {
		return fmt.Errorf("transition from %s to %s requires manager approval", req.FromLevel, req.ToLevel)
	}

	// Eval must pass for forward promotions (not rollback).
	if req.ToLevel != PromotionC0Sandbox {
		if req.EvalResult == nil || !req.EvalResult.Passed {
			return fmt.Errorf("eval must pass for promotion to %s", req.ToLevel)
		}
	}

	// Update skill level in store.
	if err := l.store.UpdateSkillLevel(ctx, req.SkillID, req.ToLevel); err != nil {
		return fmt.Errorf("failed to update skill level: %w", err)
	}

	// Create ProofGraph TRUST_EVENT node.
	payload, err := json.Marshal(map[string]interface{}{
		"action":     "PROMOTED",
		"skill_id":   req.SkillID,
		"from_level": req.FromLevel,
		"to_level":   req.ToLevel,
		"actor":      req.RequestedBy,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal proof payload: %w", err)
	}

	node, err := l.graph.Append(proofgraph.NodeTypeTrustEvent, payload, req.RequestedBy, 0)
	if err != nil {
		return fmt.Errorf("failed to append proof graph node: %w", err)
	}

	now := time.Now()
	req.Status = "APPROVED"
	req.ResolvedAt = &now
	req.ProofGraphNode = node.NodeHash

	// Append lineage entry.
	lineageEntry := &SkillLineageEntry{
		EntryID:        uuid.New().String(),
		SkillID:        req.SkillID,
		Version:        0, // Caller should set proper version
		Action:         "PROMOTED",
		FromLevel:      req.FromLevel,
		ToLevel:        req.ToLevel,
		ActorID:        req.RequestedBy,
		ContentHash:    "", // Caller should set if needed
		ProofGraphNode: node.NodeHash,
		Timestamp:      now,
	}
	if err := l.store.AppendLineage(ctx, lineageEntry); err != nil {
		return fmt.Errorf("failed to append lineage: %w", err)
	}

	return nil
}

// Rollback demotes a skill back to C0_SANDBOX.
// Creates ProofGraph TRUST_EVENT node.
func (l *PromotionLadder) Rollback(ctx context.Context, skillID, actorID, reason string) error {
	skill, err := l.store.GetSkill(ctx, skillID)
	if err != nil {
		return fmt.Errorf("failed to get skill: %w", err)
	}

	if skill.Level == PromotionC0Sandbox {
		return fmt.Errorf("skill %s is already at C0_SANDBOX", skillID)
	}

	fromLevel := skill.Level

	if err := l.store.UpdateSkillLevel(ctx, skillID, PromotionC0Sandbox); err != nil {
		return fmt.Errorf("failed to update skill level: %w", err)
	}

	payload, err := json.Marshal(map[string]interface{}{
		"action":     "ROLLED_BACK",
		"skill_id":   skillID,
		"from_level": fromLevel,
		"to_level":   PromotionC0Sandbox,
		"actor":      actorID,
		"reason":     reason,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal proof payload: %w", err)
	}

	node, err := l.graph.Append(proofgraph.NodeTypeTrustEvent, payload, actorID, 0)
	if err != nil {
		return fmt.Errorf("failed to append proof graph node: %w", err)
	}

	lineageEntry := &SkillLineageEntry{
		EntryID:        uuid.New().String(),
		SkillID:        skillID,
		Version:        skill.Version,
		Action:         "ROLLED_BACK",
		FromLevel:      fromLevel,
		ToLevel:        PromotionC0Sandbox,
		ActorID:        actorID,
		ContentHash:    skill.ContentHash,
		ProofGraphNode: node.NodeHash,
		Timestamp:      time.Now(),
	}
	if err := l.store.AppendLineage(ctx, lineageEntry); err != nil {
		return fmt.Errorf("failed to append lineage: %w", err)
	}

	return nil
}
