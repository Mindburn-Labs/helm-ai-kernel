package provision

// The stage ceiling (helm-tracker#334, modes L1) as a pure rule: a plan's stage
// bounds what its mandates grant, judged from the gateway's declarations. The
// Postgres proofs of the same rules at Propose and at Apply are in package
// admission (stage_ceiling_postgres_test.go).

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// stageCatalog declares a read, a provider write and an internal write.
var stageCatalog = adapters.Catalog{
	"svc.read":     {EffectType: "svc.read", Reversible: adapters.ReversibleNotApplicable},
	"svc.write":    {EffectType: "svc.write", Reversible: adapters.ReversibleYes},
	"svc.publish":  {EffectType: "svc.publish", Reversible: adapters.ReversibleNo},
	"work.record":  {EffectType: "work.record", Reversible: adapters.ReversibleNo, Internal: true},
	"work.inspect": {EffectType: "work.inspect", Reversible: adapters.ReversibleNotApplicable, Internal: true},
}

// stagePlan is a plan at stage with one mandate whose terms are terms.
func stagePlan(stage string, terms effectargs.PlanTerms) *effectargs.Plan {
	return &effectargs.Plan{Stage: stage, OrgRef: "org:acme", Mandates: []effectargs.PlanMandate{{Node: "org:acme", Holder: "org:acme", Terms: terms}}}
}

func grants(effects ...string) effectargs.PlanTerms {
	return effectargs.PlanTerms{EffectTypes: effects}
}

func behindApproval(effects ...string) effectargs.PlanTerms {
	return effectargs.PlanTerms{EffectTypes: effects, ApprovalRequired: effects}
}

func TestStageCeilingDraftGrantsNoWriteButAnInternalOne(t *testing.T) {
	for _, ok := range []effectargs.PlanTerms{grants("svc.read"), grants("work.record", "work.inspect", "svc.read"), behindApproval("work.record")} {
		if r := CheckStage(stagePlan(effectargs.StageDraft, ok), stageCatalog); r != nil {
			t.Errorf("draft %v: %v", ok.EffectTypes, r)
		}
	}
	for name, bad := range map[string]effectargs.PlanTerms{
		"a reversible write":           grants("svc.write"),
		"an irreversible write":        grants("svc.read", "svc.publish"),
		"a write behind approval":      behindApproval("svc.write"),
		"an undeclared effect type":    grants("svc.unknown"),
		"an internal and a real write": grants("work.record", "svc.write"),
	} {
		r := CheckStage(stagePlan(effectargs.StageDraft, bad), stageCatalog)
		if r == nil || r.Reason != contracts.ReasonStageCeilingExceeded {
			t.Errorf("draft with %s: %v", name, r)
		}
	}
	// Internal is the gateway's declaration, never a name: without the
	// declaration, the same effect type is a write like any other.
	if r := CheckStage(stagePlan(effectargs.StageDraft, grants("work.record")), adapters.Catalog{}); r == nil {
		t.Error("an internal write passed draft with no declaration")
	}
	// A child mandate is held to the stage like the root.
	p := stagePlan(effectargs.StageDraft, grants("svc.read"))
	p.Mandates = append(p.Mandates, effectargs.PlanMandate{Node: "team:a", Holder: "team:a", Parent: "org:acme", Terms: grants("svc.write")})
	if r := CheckStage(p, stageCatalog); r == nil || !strings.Contains(r.Detail, `"team:a"`) {
		t.Errorf("a draft child granting a write: %v", r)
	}
}

func TestStageCeilingApprovalRequiredPutsEveryWriteBehindApproval(t *testing.T) {
	threshold := int64(5)
	for _, ok := range []effectargs.PlanTerms{
		grants("svc.read"),
		behindApproval("svc.write"),
		behindApproval("svc.write", "svc.publish", "work.record"),
		{EffectTypes: []string{"svc.read"}, ApprovalThreshold: &threshold},
	} {
		if r := CheckStage(stagePlan(effectargs.StageApprovalRequired, ok), stageCatalog); r != nil {
			t.Errorf("approval-required %+v: %v", ok, r)
		}
	}
	for name, bad := range map[string]effectargs.PlanTerms{
		"a write without approval":          grants("svc.write"),
		"an internal write without one":     grants("work.record"),
		"one of two writes behind approval": {EffectTypes: []string{"svc.write", "svc.publish"}, ApprovalRequired: []string{"svc.write"}},
		"a write behind a threshold only":   {EffectTypes: []string{"svc.write"}, ApprovalThreshold: &threshold},
		"a write behind both":               {EffectTypes: []string{"svc.write"}, ApprovalRequired: []string{"svc.write"}, ApprovalThreshold: &threshold},
		"an undeclared effect without one":  grants("svc.unknown"),
	} {
		r := CheckStage(stagePlan(effectargs.StageApprovalRequired, bad), stageCatalog)
		if r == nil || r.Reason != contracts.ReasonStageCeilingExceeded {
			t.Errorf("approval-required with %s: %v", name, r)
		}
	}
}

// constrained-live and certified-live grant by mandate terms only; certified-
// live grants nothing more than constrained-live.
func TestStageCeilingLiveStagesGrantByMandateTerms(t *testing.T) {
	for _, stage := range []string{effectargs.StageConstrainedLive, effectargs.StageCertifiedLive} {
		for _, terms := range []effectargs.PlanTerms{grants("svc.write", "svc.publish"), grants("svc.unknown"), behindApproval("svc.write")} {
			if r := CheckStage(stagePlan(stage, terms), stageCatalog); r != nil {
				t.Errorf("%s %v: %v", stage, terms.EffectTypes, r)
			}
		}
	}
	if r := CheckStage(stagePlan("live", grants("svc.read")), stageCatalog); r == nil || r.Reason != contracts.ReasonSchemaViolation {
		t.Errorf("a stage that is not one: %v", r)
	}
}

// A narrowing plan needs no approval, so it never raises the rung; lowering
// it, or keeping it, is a narrowing like any other.
func TestPrecheckNarrowNeverRaisesTheStage(t *testing.T) {
	raw := example(t, "narrow.v1.valid.json")
	c, err := Check(effectargs.AuthorityNarrow, raw)
	if err != nil {
		t.Fatal(err)
	}
	applied := &Applied{OrgRef: c.Plan.OrgRef, Digest: c.Plan.BaseDigest, Provisioner: "svc:helm-org"}
	for _, n := range c.Nodes {
		applied.Nodes = append(applied.Nodes, AppliedNode{Node: n.Name})
	}
	for _, p := range c.Plan.Principals {
		applied.Principals = append(applied.Principals, AppliedPrincipal{ID: p.ID, Kind: p.Kind})
	}
	at := func(stage string) *Compiled {
		p := *c.Plan
		p.Stage = stage
		p.Digest = strings.Repeat("5", 64)
		return &Compiled{Plan: &p, Nodes: c.Nodes}
	}
	ranks := []string{effectargs.StageDraft, effectargs.StageApprovalRequired, effectargs.StageConstrainedLive, effectargs.StageCertifiedLive}
	for i, from := range ranks {
		applied.Stage = from
		for j, to := range ranks {
			r := Precheck(at(to), applied, "svc:helm-org")
			switch {
			case j > i && (r == nil || r.Reason != contracts.ReasonStageRaiseRequiresProvision):
				t.Errorf("narrowing %s -> %s: %v", from, to, r)
			case j <= i && r != nil:
				t.Errorf("narrowing %s -> %s refused: %v", from, to, r)
			}
		}
	}
	// A provision plan raises the stage: it waits for a distinct human.
	pc, err := Check(effectargs.AuthorityProvision, example(t, "provision.v1.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	raise := *pc.Plan
	raise.Stage, raise.BaseDigest = effectargs.StageCertifiedLive, applied.Digest
	applied.Stage = effectargs.StageDraft
	if r := Precheck(&Compiled{Plan: &raise, Nodes: pc.Nodes}, applied, "svc:helm-org"); r != nil {
		t.Errorf("a provision plan raising the stage: %v", r)
	}
	// An applied stage the gateway does not know is not a floor to raise from.
	applied.Stage = "unknown"
	if r := Precheck(at(effectargs.StageDraft), applied, "svc:helm-org"); r == nil {
		t.Error("a narrowing over an applied stage that is not one passed")
	}
}
