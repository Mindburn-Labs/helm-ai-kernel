package scenarios

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel"
)

// Scenario 5: Crypto Miner / Resource Hijack
//
// Threat: Unauthorized compute resource consumption by a compromised agent
// that attempts to run a cryptocurrency miner.
// Expected: DENY with SYSTEM_FROZEN (when detected) or BUDGET_EXCEEDED.
func TestCryptoMiner_FreezeStopsAllExecution(t *testing.T) {
	fc := kernel.NewFreezeController()

	// Security team detects crypto miner, activates freeze
	receipt, err := fc.Freeze("security-responder")
	if err != nil {
		t.Fatalf("freeze failed: %v", err)
	}
	if receipt.Action != "freeze" {
		t.Errorf("action = %s, want freeze", receipt.Action)
	}

	// All subsequent operations should be blocked
	if !fc.IsFrozen() {
		t.Error("system should be frozen after security response")
	}

	// Risk summary shows CRITICAL
	rs := contracts.ComputeRiskSummary(contracts.EffectTypeCloudComputeBudget, contracts.WithFrozen(), contracts.WithBudgetImpact())
	if rs.OverallRisk != "CRITICAL" {
		t.Errorf("frozen + budget impact = %s, want CRITICAL", rs.OverallRisk)
	}
	if !rs.BudgetImpact {
		t.Error("BudgetImpact should be true")
	}
}

func TestCryptoMiner_BudgetEffectClassification(t *testing.T) {
	et := contracts.LookupEffectType(contracts.EffectTypeCloudComputeBudget)
	if et == nil {
		t.Fatal("CLOUD_COMPUTE_BUDGET not found")
	}
	if et.Classification.Reversibility != "compensatable" {
		t.Errorf("reversibility = %s, want compensatable", et.Classification.Reversibility)
	}
	if !et.CompensationRequired {
		t.Error("CLOUD_COMPUTE_BUDGET should require compensation")
	}

	rc := contracts.EffectRiskClass(contracts.EffectTypeCloudComputeBudget)
	if rc != "E2" {
		t.Errorf("risk class = %s, want E2", rc)
	}
}

func TestCryptoMiner_UnfreezeRestoresOperations(t *testing.T) {
	fc := kernel.NewFreezeController()
	fc.Freeze("security-responder")

	receipt, err := fc.Unfreeze("security-lead")
	if err != nil {
		t.Fatalf("unfreeze failed: %v", err)
	}
	if receipt.Action != "unfreeze" {
		t.Errorf("action = %s, want unfreeze", receipt.Action)
	}
	if fc.IsFrozen() {
		t.Error("system should be unfrozen after resolution")
	}

	// Verify audit trail
	receipts := fc.Receipts()
	if len(receipts) != 2 {
		t.Errorf("receipt count = %d, want 2 (freeze + unfreeze)", len(receipts))
	}
}
