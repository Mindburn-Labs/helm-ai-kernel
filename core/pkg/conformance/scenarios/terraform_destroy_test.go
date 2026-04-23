package scenarios

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/governance"
)

// Scenario 1: Terraform Destroy / Protected DB
//
// Threat: Agent attempts to destroy production infrastructure (terraform destroy).
// Expected: DENY with APPROVAL_REQUIRED — E4 effect requires dual-control approval.
func TestTerraformDestroy_DeniedWithoutApproval(t *testing.T) {
	// Verify effect type exists and is classified correctly
	et := contracts.LookupEffectType(contracts.EffectTypeInfraDestroy)
	if et == nil {
		t.Fatal("INFRA_DESTROY effect type not found in catalog")
	}
	if et.Classification.Reversibility != "irreversible" {
		t.Errorf("INFRA_DESTROY reversibility = %s, want irreversible", et.Classification.Reversibility)
	}
	if et.Classification.BlastRadius != "system_wide" {
		t.Errorf("INFRA_DESTROY blast_radius = %s, want system_wide", et.Classification.BlastRadius)
	}
	if et.DefaultApprovalLevel != "dual_control" {
		t.Errorf("INFRA_DESTROY approval = %s, want dual_control", et.DefaultApprovalLevel)
	}

	// Verify risk class
	rc := contracts.EffectRiskClass(contracts.EffectTypeInfraDestroy)
	if rc != "E4" {
		t.Errorf("INFRA_DESTROY risk class = %s, want E4", rc)
	}

	// Verify risk summary
	rs := contracts.ComputeRiskSummary(contracts.EffectTypeInfraDestroy)
	if rs.OverallRisk != "CRITICAL" {
		t.Errorf("INFRA_DESTROY overall risk = %s, want CRITICAL", rs.OverallRisk)
	}
	if !rs.ApprovalRequired {
		t.Error("INFRA_DESTROY should require approval")
	}

	// Verify plan→commit blocks without approval
	pc := governance.NewPlanCommitController()
	plan := &governance.ExecutionPlan{
		PlanID:      "terraform-destroy-prod-db",
		EffectType:  contracts.EffectTypeInfraDestroy,
		EffectClass: "E4",
		Principal:   "agent-terraform",
		Description: "terraform destroy -target=aws_rds_instance.production",
	}

	ref, err := pc.SubmitPlan(plan)
	if err != nil {
		t.Fatalf("SubmitPlan failed: %v", err)
	}

	// No approval given — should timeout
	decision, err := pc.WaitForApproval(*ref, 50*_ms)
	if err != nil {
		t.Fatalf("WaitForApproval failed: %v", err)
	}
	if decision.Status != governance.PlanStatusTimeout {
		t.Errorf("without approval, status = %s, want TIMEOUT", decision.Status)
	}
}

func TestTerraformDestroy_AllowedWithApproval(t *testing.T) {
	pc := governance.NewPlanCommitController()
	plan := &governance.ExecutionPlan{
		PlanID:      "terraform-destroy-staging",
		EffectType:  contracts.EffectTypeInfraDestroy,
		EffectClass: "E4",
		Principal:   "agent-terraform",
		Description: "terraform destroy -target=aws_rds_instance.staging",
	}

	ref, _ := pc.SubmitPlan(plan)

	// Approve in background
	go func() { pc.Approve("terraform-destroy-staging", "infrastructure-lead") }()

	decision, err := pc.WaitForApproval(*ref, 1*_sec)
	if err != nil {
		t.Fatalf("WaitForApproval failed: %v", err)
	}
	if decision.Status != governance.PlanStatusApproved {
		t.Errorf("with approval, status = %s, want APPROVED", decision.Status)
	}
}
