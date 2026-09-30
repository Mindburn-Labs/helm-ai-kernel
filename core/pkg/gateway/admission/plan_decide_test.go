package admission

// The pure decision for the gateway's own authority effects (contract 5):
// they need no proposer mandate, only a registered service principal, and a
// provision plan needs a distinct approver while a narrowing plan needs none.
//
// quantum_posture: no cryptography; signs and verifies nothing.

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

// planInput is a plan proposed by the organization's service principal: no
// effect-type row, no mandate and no limit.
func planInput(t *testing.T, effectType string) Input {
	t.Helper()
	in := decideBase(t)
	in.EffectType, in.Target, in.RiskClass, in.EffectTypeFound = effectType, "org:acme", mandates.RiskIrreversible, false
	in.Chain = nil
	in.MandateFree, in.PrincipalID, in.PrincipalKind = true, "svc:helm-org", string(mandates.PrincipalService)
	return in
}

func TestDecideProvisionPlanNeedsADistinctApprovalAndNoMandate(t *testing.T) {
	in := planInput(t, effectargs.AuthorityProvision)
	if d := Decide(in); d.Verdict != Escalate || d.Reason != contracts.ReasonApprovalRequired {
		t.Fatalf("a provision plan without approval = %+v, want an escalation", d)
	}
	in.Approval = &ApprovalState{ApproverID: "usr_owner", Approved: true}
	if d := Decide(in); d.Verdict != Allow {
		t.Fatalf("a provision plan approved by a distinct human = %+v", d)
	}
	in.Approval = &ApprovalState{ApproverID: "svc:helm-org", Approved: true}
	if d := Decide(in); d.Verdict != Deny || d.Reason != contracts.ReasonApproverNotDistinct {
		t.Fatalf("a provision plan approved by its requester = %+v", d)
	}
	in.Approval = &ApprovalState{ApproverID: "usr_owner", Approved: false}
	if d := Decide(in); d.Verdict != Deny || d.Reason != contracts.ReasonApprovalRejected {
		t.Fatalf("a rejected provision plan = %+v", d)
	}
}

func TestDecideNarrowPlanNeedsNoApproval(t *testing.T) {
	in := planInput(t, effectargs.AuthorityNarrow)
	in.RiskClass = mandates.RiskMedium
	if d := Decide(in); d.Verdict != Allow {
		t.Fatalf("a narrowing plan = %+v, want it allowed at once", d)
	}
	in.ActiveStops = []string{"s"}
	if d := Decide(in); d.Verdict != Deny || d.Reason != contracts.ReasonEmergencyStopFenced {
		t.Fatalf("a narrowing plan under a stop that applies to it = %+v", d)
	}
}

func TestDecidePlanRequesterMustBeARegisteredServicePrincipal(t *testing.T) {
	for _, effectType := range []string{effectargs.AuthorityProvision, effectargs.AuthorityNarrow} {
		for name, edit := range map[string]func(*Input){
			"a human":      func(in *Input) { in.PrincipalKind = string(mandates.PrincipalHuman) },
			"an agent":     func(in *Input) { in.PrincipalKind = string(mandates.PrincipalAgent) },
			"no kind":      func(in *Input) { in.PrincipalKind = "" },
			"unregistered": func(in *Input) { in.PrincipalFound = false },
			"disabled":     func(in *Input) { in.PrincipalActive = false },
		} {
			in := planInput(t, effectType)
			edit(&in)
			want := contracts.ReasonInsufficientPrivilege
			if name == "unregistered" || name == "disabled" {
				want = contracts.ReasonPrincipalInactive
			}
			if d := Decide(in); d.Verdict != Deny || d.Reason != want {
				t.Errorf("%s proposing %s: Decide = %+v, want a denial with %s", name, effectType, d, want)
			}
		}
	}
}

// Step-up covers a provision plan, which widens, and not a narrowing plan,
// which never reaches an approver.
func TestStepUpCoversProvisionPlansButNotNarrowing(t *testing.T) {
	for _, test := range []struct {
		risk, effectType string
		want             bool
	}{
		{"irreversible", effectargs.AuthorityProvision, true},
		{"low", effectargs.AuthorityProvision, true},
		{"medium", effectargs.AuthorityNarrow, false},
		{"low", effectargs.AuthorityNarrow, false},
	} {
		if got := needsStepUp(test.risk, test.effectType); got != test.want {
			t.Errorf("%s %s: needsStepUp = %v, want %v", test.risk, test.effectType, got, test.want)
		}
	}
	for effectType, want := range map[string]bool{
		effectargs.AuthorityProvision: true, effectargs.AuthorityLift: true, "helm.authority.grant": true,
		effectargs.AuthorityNarrow: false, "github.repository.get": false,
	} {
		if got := effectargs.WidensAuthority(effectType); got != want {
			t.Errorf("WidensAuthority(%s) = %v, want %v", effectType, got, want)
		}
	}
}
