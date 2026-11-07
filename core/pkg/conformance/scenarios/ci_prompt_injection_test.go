package scenarios

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

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
