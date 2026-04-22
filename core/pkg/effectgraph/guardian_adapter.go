package effectgraph

import (
	"context"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
)

// GuardianAdapter bridges guardian.Guardian to the PolicyEvaluator interface,
// allowing the GraphEvaluator to evaluate plan steps through the real Guardian PEP.
type GuardianAdapter struct {
	guardian *guardian.Guardian
}

// NewGuardianAdapter creates an adapter that wraps a real Guardian.
func NewGuardianAdapter(g *guardian.Guardian) *GuardianAdapter {
	return &GuardianAdapter{guardian: g}
}

// EvaluateStep evaluates a plan step through the Guardian's policy engine.
func (a *GuardianAdapter) EvaluateStep(ctx context.Context, step *contracts.PlanStep, actor string) (*contracts.DecisionRecord, error) {
	req := guardian.DecisionRequest{
		Principal: actor,
		Action:    step.EffectType,
		Resource:  step.ID,
		Context: map[string]interface{}{
			"step_id":           step.ID,
			"description":       step.Description,
			"effect_type":       step.EffectType,
			"requested_backend": step.RequestedBackend,
			"requested_profile": step.RequestedProfile,
		},
	}

	// Copy step params into context for policy evaluation.
	for k, v := range step.Params {
		req.Context["param."+k] = v
	}

	decision, err := a.guardian.EvaluateDecision(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("guardian evaluate: %w", err)
	}
	return decision, nil
}

// IssueIntent issues a signed execution intent for an ALLOW decision.
func (a *GuardianAdapter) IssueIntent(ctx context.Context, decision *contracts.DecisionRecord, step *contracts.PlanStep) (*contracts.AuthorizedExecutionIntent, error) {
	if decision.Verdict != string(contracts.VerdictAllow) {
		return nil, fmt.Errorf("cannot issue intent for verdict %s", decision.Verdict)
	}

	effect := &contracts.Effect{
		EffectID:   "eff-" + step.ID,
		EffectType: step.EffectType,
		Params:     step.Params,
	}

	intent, err := a.guardian.IssueExecutionIntent(ctx, decision, effect)
	if err != nil {
		return nil, fmt.Errorf("guardian issue intent: %w", err)
	}
	return intent, nil
}
