package provision

import (
	"slices"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// CheckStage holds a plan to its stage (helm-tracker#334): the stage is a
// ceiling on what the plan's mandates grant, judged from catalog, the
// declarations of the effect types the gateway performs, never from anything
// the plan or its proposer says about an effect. It is pure. Propose runs it
// so that no approver is asked for a plan that cannot apply, and Apply runs it
// again before it writes.
//
// A write is an effect type whose declaration's Reversible is not "not
// applicable"; an effect type catalog does not declare cannot be shown to be a
// read, and counts as a write.
//
//   - draft: no mandate grants a write, except one declared Internal (it
//     changes only the composing Control Plane's own rows).
//   - approval-required: every write a mandate grants is in its
//     approval_required, and that mandate sets no approval_threshold, so every
//     call of it waits for a distinct human.
//   - constrained-live and certified-live: the mandate terms alone; certified-
//     live grants nothing constrained-live does not. Certification is the
//     Control Plane's evidence, which the gateway does not claim.
//
// Every refusal is STAGE_CEILING_EXCEEDED.
func CheckStage(plan *effectargs.Plan, catalog adapters.Catalog) *adapters.Refusal {
	switch plan.Stage {
	case effectargs.StageConstrainedLive, effectargs.StageCertifiedLive:
		return nil
	case effectargs.StageDraft, effectargs.StageApprovalRequired:
	default:
		return adapters.Refuse(contracts.ReasonSchemaViolation, "stage %q is not a stage", plan.Stage)
	}
	for _, m := range plan.Mandates {
		for _, effectType := range m.Terms.EffectTypes {
			d, declared := catalog[effectType]
			if declared && !d.Writes() {
				continue
			}
			what := "a write"
			if !declared {
				what = "an effect type this gateway does not declare, which counts as a write"
			}
			switch plan.Stage {
			case effectargs.StageDraft:
				if declared && d.Internal {
					continue
				}
				return adapters.Refuse(contracts.ReasonStageCeilingExceeded,
					"stage draft grants no write but an internal one: mandate %q grants %s, %s", m.Node, effectType, what)
			case effectargs.StageApprovalRequired:
				if !slices.Contains(m.Terms.ApprovalRequired, effectType) {
					return adapters.Refuse(contracts.ReasonStageCeilingExceeded,
						"stage approval-required puts every write behind an approval: mandate %q grants %s, %s, without listing it in approval_required",
						m.Node, effectType, what)
				}
				if m.Terms.ApprovalThreshold != nil {
					return adapters.Refuse(contracts.ReasonStageCeilingExceeded,
						"stage approval-required puts every write behind an approval: mandate %q grants %s with an approval_threshold", m.Node, effectType)
				}
			}
		}
	}
	return nil
}

// checkStageRaise refuses a narrowing plan whose stage ranks above the applied
// plan's: a narrowing plan needs no approval, so a rung is raised only by a
// provision plan, which a distinct human approves (STAGE_RAISE_REQUIRES_PROVISION).
func checkStageRaise(plan *effectargs.Plan, applied *Applied) *adapters.Refusal {
	if effectargs.StageRank(plan.Stage) > effectargs.StageRank(applied.Stage) {
		return adapters.Refuse(contracts.ReasonStageRaiseRequiresProvision,
			"a narrowing plan does not raise the stage from %s to %s: that is a provision plan, which a distinct human approves",
			applied.Stage, plan.Stage)
	}
	return nil
}
