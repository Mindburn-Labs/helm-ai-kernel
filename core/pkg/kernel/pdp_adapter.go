// Package kernel provides PDP integration for the effect boundary.
// Per Section 1.4 - Effect Interception Boundary
package kernel

import (
	"context"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/governance"
)

// GovernancePDPAdapter adapts the governance.PolicyDecisionPoint to kernel.PDPEvaluator.
type GovernancePDPAdapter struct {
	pdp governance.PolicyDecisionPoint
}

// NewGovernancePDPAdapter creates an adapter for the governance PDP.
func NewGovernancePDPAdapter(pdp governance.PolicyDecisionPoint) *GovernancePDPAdapter {
	return &GovernancePDPAdapter{pdp: pdp}
}

// Evaluate implements PDPEvaluator for the effect boundary.
func (a *GovernancePDPAdapter) Evaluate(ctx context.Context, req *EffectRequest) (string, string, error) {
	// Build PDP request from effect request
	pdpReq := governance.PDPRequest{
		RequestID: req.EffectID,
		Effect: governance.EffectDescriptor{
			EffectID:          req.EffectID,
			EffectType:        string(req.EffectType),
			EffectPayloadHash: req.Payload.PayloadHash,
		},
		Subject: governance.SubjectDescriptor{
			ActorID:   req.Subject.SubjectID,
			ActorType: req.Subject.SubjectType,
			AuthContext: governance.AuthContext{
				SessionID: req.Subject.SessionID,
			},
		},
		Context: governance.ContextDescriptor{
			Time: governance.TimeDescriptor{
				DecisionTimeSource: "observed_at",
				Timestamp:          req.SubmittedAt,
			},
		},
	}

	// Add context if available
	if req.Context != nil {
		pdpReq.Context.ModeID = req.Context.ModeID
		pdpReq.Context.LoopID = req.Context.LoopID
		pdpReq.Context.PhenotypeHash = req.Context.PhenotypeHash
		pdpReq.Context.EnvironmentSnapshotHash = req.Context.EnvironmentID
	}

	// Add idempotency key
	if req.Idempotency != nil {
		pdpReq.Effect.IdempotencyKey = req.Idempotency.Key
	}

	// Invoke PDP
	resp, err := a.pdp.Evaluate(ctx, pdpReq)
	if err != nil {
		return "DENY", "", err
	}

	// Map decision
	decision := "DENY"
	switch resp.Decision {
	case governance.DecisionAllow:
		decision = "ALLOW"
	case governance.DecisionDeny:
		decision = "DENY"
	case governance.DecisionRequireApproval:
		decision = "REQUIRE_APPROVAL"
	case governance.DecisionRequireEvidence:
		decision = "REQUIRE_EVIDENCE"
	case governance.DecisionDefer:
		decision = "DEFER"
	}

	return decision, resp.DecisionID, nil
}

// WiredEffectBoundary creates a fully wired effect boundary with PDP integration.
type WiredEffectBoundary struct {
	*InMemoryEffectBoundary
	pdpAdapter *GovernancePDPAdapter
}

// NewWiredEffectBoundary creates an effect boundary wired to the governance PDP.
func NewWiredEffectBoundary(pdp governance.PolicyDecisionPoint, log EventLog) *WiredEffectBoundary {
	adapter := NewGovernancePDPAdapter(pdp)
	boundary := NewInMemoryEffectBoundary(adapter, log)

	return &WiredEffectBoundary{
		InMemoryEffectBoundary: boundary,
		pdpAdapter:             adapter,
	}
}

// IntegratedPDPTest removed - was dead code
