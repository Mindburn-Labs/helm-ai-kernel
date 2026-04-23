package contracts

import "testing"

func TestComputeRiskSummary_E4Critical(t *testing.T) {
	rs := ComputeRiskSummary(EffectTypeInfraDestroy)
	if rs.OverallRisk != "CRITICAL" {
		t.Errorf("INFRA_DESTROY risk = %s, want CRITICAL", rs.OverallRisk)
	}
	if !rs.ApprovalRequired {
		t.Error("E4 should require approval")
	}
	if rs.EffectClass != "E4" {
		t.Errorf("effect class = %s, want E4", rs.EffectClass)
	}
}

func TestComputeRiskSummary_E3High(t *testing.T) {
	rs := ComputeRiskSummary(EffectTypeEnvRecreate)
	if rs.OverallRisk != "HIGH" {
		t.Errorf("ENV_RECREATE risk = %s, want HIGH", rs.OverallRisk)
	}
	if !rs.ApprovalRequired {
		t.Error("E3 should require approval")
	}
}

func TestComputeRiskSummary_E2Medium(t *testing.T) {
	rs := ComputeRiskSummary(EffectTypeCloudComputeBudget)
	if rs.OverallRisk != "MEDIUM" {
		t.Errorf("CLOUD_COMPUTE_BUDGET risk = %s, want MEDIUM", rs.OverallRisk)
	}
}

func TestComputeRiskSummary_E2WithBudgetImpact(t *testing.T) {
	rs := ComputeRiskSummary(EffectTypeCloudComputeBudget, WithBudgetImpact())
	if rs.OverallRisk != "HIGH" {
		t.Errorf("CLOUD_COMPUTE_BUDGET with budget impact = %s, want HIGH", rs.OverallRisk)
	}
}

func TestComputeRiskSummary_E1Low(t *testing.T) {
	rs := ComputeRiskSummary(EffectTypeAgentIdentityIsolation)
	if rs.OverallRisk != "LOW" {
		t.Errorf("AGENT_IDENTITY_ISOLATION risk = %s, want LOW", rs.OverallRisk)
	}
}

func TestComputeRiskSummary_Frozen(t *testing.T) {
	rs := ComputeRiskSummary(EffectTypeAgentIdentityIsolation, WithFrozen())
	if rs.OverallRisk != "CRITICAL" {
		t.Errorf("frozen system risk = %s, want CRITICAL", rs.OverallRisk)
	}
}

func TestComputeRiskSummary_ContextMismatch(t *testing.T) {
	rs := ComputeRiskSummary(EffectTypeAgentIdentityIsolation, WithContextMismatch())
	if rs.OverallRisk != "CRITICAL" {
		t.Errorf("context mismatch risk = %s, want CRITICAL", rs.OverallRisk)
	}
}

func TestComputeRiskSummary_MultipleFlagsCompose(t *testing.T) {
	rs := ComputeRiskSummary(EffectTypeDataEgress, WithEgressRisk(), WithIdentityRisk())
	if rs.OverallRisk != "CRITICAL" {
		t.Errorf("DATA_EGRESS with egress+identity risk = %s, want CRITICAL", rs.OverallRisk)
	}
	if !rs.EgressRisk {
		t.Error("EgressRisk should be true")
	}
	if !rs.IdentityRisk {
		t.Error("IdentityRisk should be true")
	}
}

func TestComputeRiskSummary_UnknownEffectFailClosed(t *testing.T) {
	rs := ComputeRiskSummary("UNKNOWN_EFFECT_TYPE")
	if rs.EffectClass != "E3" { // fail-closed from EffectRiskClass
		t.Errorf("unknown effect class = %s, want E3", rs.EffectClass)
	}
	if rs.OverallRisk != "HIGH" {
		t.Errorf("unknown effect risk = %s, want HIGH", rs.OverallRisk)
	}
}
