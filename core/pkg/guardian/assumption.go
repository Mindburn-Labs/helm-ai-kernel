package guardian

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

// ContextAssumptions is the request-context key carrying the assumptions an
// action depends on.
const ContextAssumptions = "assumptions"

// AssumptionObserver re-reads the current state of an assumption's subject.
//
// Implementations must be side-effect free: this runs during authorization,
// before any effect is permitted, and a failure here denies.
type AssumptionObserver interface {
	// Observe returns the current content hash for the assumption's subject.
	// An error means the state could not be confirmed, which is treated as
	// stale — a gate that cannot check cannot vouch.
	Observe(ctx context.Context, assumption contracts.ObservedAssumption) (string, error)
}

// AssumptionFreshnessInterceptor refuses an action whose declared assumptions
// no longer hold.
//
// This is the first emit site for ERR_ASSUMPTION_STALE, which has been
// declared in the reason-code registry, given a conformance vector, and
// unreachable since — because no type could express an assumption a machine
// could re-check. It closes that gap for assumptions that are declared.
//
// It does not decide when an assumption is *required*. An action that
// declares none passes through untouched. Requiring assumptions for
// side-effectful actions is a policy question and belongs in the policy
// bundle, not in a gate that would have to guess what counts as a write.
type AssumptionFreshnessInterceptor struct {
	g *Guardian
}

func NewAssumptionFreshnessInterceptor(g *Guardian) *AssumptionFreshnessInterceptor {
	return &AssumptionFreshnessInterceptor{g: g}
}

func (a *AssumptionFreshnessInterceptor) Evaluate(ctx context.Context, evalCtx *EvaluationContext, next Handler) (*contracts.DecisionRecord, error) {
	assumptions, err := assumptionsFromContext(evalCtx.Request.Context)
	if err != nil {
		return a.deny(evalCtx, contracts.ObservedAssumption{}, fmt.Sprintf("assumptions are malformed and cannot be checked: %v", err))
	}
	if len(assumptions) == 0 {
		return next(ctx, evalCtx)
	}

	now := a.g.clock.Now()
	for _, assumption := range assumptions {
		if err := assumption.Validate(); err != nil {
			return a.deny(evalCtx, assumption, err.Error())
		}
		if assumption.Expired(now) {
			return a.deny(evalCtx, assumption, fmt.Sprintf(
				"observation of %q expired at %s", assumption.Subject, assumption.ExpiresAt().UTC().Format("2006-01-02T15:04:05Z")))
		}

		// Within its window an observation is taken on trust unless an
		// observer can say otherwise. With one injected, the window is a
		// ceiling rather than the whole check.
		if a.g.assumptionObserver == nil {
			continue
		}
		observed, obsErr := a.g.assumptionObserver.Observe(ctx, assumption)
		if obsErr != nil {
			return a.deny(evalCtx, assumption, fmt.Sprintf(
				"state of %q could not be confirmed: %v", assumption.Subject, obsErr))
		}
		if observed != assumption.ContentHash {
			return a.deny(evalCtx, assumption, fmt.Sprintf(
				"state of %q changed since it was observed", assumption.Subject))
		}
	}

	return next(ctx, evalCtx)
}

// deny mints the refusal. The MustBindEvidence triple from the conformance
// vector — plan_hash, assumption_hash, receipt_id — is bound into
// InputContext, which is covered by the decision signature, so the reference
// cannot be edited after the fact.
func (a *AssumptionFreshnessInterceptor) deny(evalCtx *EvaluationContext, assumption contracts.ObservedAssumption, why string) (*contracts.DecisionRecord, error) {
	if assumption.AssumptionHash == "" {
		// Seal on the denial path too: an unhashed assumption would leave the
		// refusal with nothing to point at.
		sealed := assumption
		if err := sealed.Seal(); err == nil {
			assumption = sealed
		}
	}

	decision := &contracts.DecisionRecord{
		ID:         newDecisionID(),
		Timestamp:  a.g.clock.Now(),
		Verdict:    string(contracts.VerdictDeny),
		Reason:     fmt.Sprintf("ERR_ASSUMPTION_STALE: %s", why),
		ReasonCode: string(contracts.ReasonAssumptionStale),
		InputContext: map[string]any{
			"assumption_hash": assumption.AssumptionHash,
			"assumption_id":   assumption.AssumptionID,
			"plan_hash":       planHashFromContext(evalCtx.Request.Context),
		},
	}
	if err := a.g.signDecisionWithContext(decision, evalCtx); err != nil {
		return nil, fmt.Errorf("failed to sign assumption-stale decision: %w", err)
	}
	a.g.recordBehavioralEvent(evalCtx.Request.Principal, trust.EventPolicyViolate, "assumption stale")
	return decision, nil
}

// assumptionsFromContext reads the declared assumptions. The value travels as
// request context, so it is JCS-hashed into EffectDigest and covered by the
// decision signature without extra plumbing — but it is caller-supplied, so
// it is a claim to be re-checked, never evidence in itself.
func assumptionsFromContext(reqCtx map[string]any) ([]contracts.ObservedAssumption, error) {
	raw, ok := reqCtx[ContextAssumptions]
	if !ok || raw == nil {
		return nil, nil
	}

	// Round-trip through JSON so a value that arrived over the wire as
	// []any{map[string]any{...}} and one built in Go both decode the same way.
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("encoding assumptions: %w", err)
	}
	var assumptions []contracts.ObservedAssumption
	if err := json.Unmarshal(encoded, &assumptions); err != nil {
		return nil, fmt.Errorf("decoding assumptions: %w", err)
	}
	return assumptions, nil
}

func planHashFromContext(reqCtx map[string]any) string {
	if hash, ok := reqCtx["plan_hash"].(string); ok {
		return hash
	}
	return ""
}
