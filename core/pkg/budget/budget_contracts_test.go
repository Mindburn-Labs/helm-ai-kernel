package budget

import (
	"encoding/json"
	"testing"
)

func TestFinal_CostJSON(t *testing.T) {
	c := Cost{Amount: 500, Currency: "USD", Reason: "api call"}
	data, _ := json.Marshal(c)
	var c2 Cost
	json.Unmarshal(data, &c2)
	if c2.Amount != 500 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_BudgetJSON(t *testing.T) {
	b := Budget{TenantID: "t1", DailyLimit: 1000, MonthlyLimit: 5000}
	data, _ := json.Marshal(b)
	var b2 Budget
	json.Unmarshal(data, &b2)
	if b2.TenantID != "t1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DecisionJSON(t *testing.T) {
	d := Decision{Allowed: true, Reason: "within budget"}
	data, _ := json.Marshal(d)
	var d2 Decision
	json.Unmarshal(data, &d2)
	if !d2.Allowed {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_EnforcementReceiptJSON(t *testing.T) {
	r := EnforcementReceipt{ID: "r1", TenantID: "t1", Action: "allowed", CostCents: 100}
	data, _ := json.Marshal(r)
	var r2 EnforcementReceipt
	json.Unmarshal(data, &r2)
	if r2.CostCents != 100 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_RiskLevelConstants(t *testing.T) {
	levels := []RiskLevel{RiskLow, RiskMedium, RiskHigh, RiskCritical}
	for _, l := range levels {
		if l == "" {
			t.Fatal("risk level must not be empty")
		}
	}
}

func TestFinal_RiskBudgetJSON(t *testing.T) {
	rb := RiskBudget{TenantID: "t1", ComputeCapMillis: 10000}
	data, _ := json.Marshal(rb)
	var rb2 RiskBudget
	json.Unmarshal(data, &rb2)
	if rb2.TenantID != "t1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_RiskDecisionJSON(t *testing.T) {
	rd := RiskDecision{Allowed: true, RiskCost: 25.5}
	data, _ := json.Marshal(rd)
	var rd2 RiskDecision
	json.Unmarshal(data, &rd2)
	if rd2.RiskCost != 25.5 {
		t.Fatal("round-trip mismatch")
	}
}
