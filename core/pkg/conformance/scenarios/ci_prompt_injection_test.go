package scenarios

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/governance"
)

// Scenario 2: CI Prompt Injection → Supply-Chain
//
// Threat: An agent in CI receives an injected prompt and attempts to
// access signing credentials and publish a malicious package.
// Expected: DENY — CI_CREDENTIAL_ACCESS is E4, requires dual-control.
func TestCIPromptInjection_CredentialAccessDenied(t *testing.T) {
	et := contracts.LookupEffectType(contracts.EffectTypeCICredentialAccess)
	if et == nil {
		t.Fatal("CI_CREDENTIAL_ACCESS not found in catalog")
	}
	if et.Classification.Reversibility != "irreversible" {
		t.Errorf("reversibility = %s, want irreversible", et.Classification.Reversibility)
	}
	if et.DefaultApprovalLevel != "dual_control" {
		t.Errorf("approval = %s, want dual_control", et.DefaultApprovalLevel)
	}

	rc := contracts.EffectRiskClass(contracts.EffectTypeCICredentialAccess)
	if rc != "E4" {
		t.Errorf("risk class = %s, want E4", rc)
	}

	// Plan submitted but no approval → timeout (denied)
	pc := governance.NewPlanCommitController()
	ref, _ := pc.SubmitPlan(&governance.ExecutionPlan{
		PlanID:      "ci-cred-access",
		EffectType:  contracts.EffectTypeCICredentialAccess,
		EffectClass: "E4",
		Principal:   "agent-ci-runner",
		Description: "npm config set //registry.npmjs.org/:_authToken=${NPM_TOKEN}",
	})

	decision, _ := pc.WaitForApproval(*ref, 50*_ms)
	if decision.Status != governance.PlanStatusTimeout {
		t.Errorf("CI credential access without approval should timeout, got %s", decision.Status)
	}
}

func TestCIPromptInjection_PublishDenied(t *testing.T) {
	et := contracts.LookupEffectType(contracts.EffectTypeSoftwarePublish)
	if et == nil {
		t.Fatal("SOFTWARE_PUBLISH not found in catalog")
	}

	rc := contracts.EffectRiskClass(contracts.EffectTypeSoftwarePublish)
	if rc != "E4" {
		t.Errorf("SOFTWARE_PUBLISH risk class = %s, want E4", rc)
	}

	rs := contracts.ComputeRiskSummary(contracts.EffectTypeSoftwarePublish)
	if rs.OverallRisk != "CRITICAL" {
		t.Errorf("SOFTWARE_PUBLISH risk = %s, want CRITICAL", rs.OverallRisk)
	}
}
