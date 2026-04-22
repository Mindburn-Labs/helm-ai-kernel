package simulation

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestFinal_OrgTwinStatusConstants(t *testing.T) {
	statuses := []OrgTwinStatus{TwinStatusCurrent, TwinStatusStale, TwinStatusDraft}
	seen := make(map[OrgTwinStatus]bool)
	for _, s := range statuses {
		if s == "" {
			t.Fatal("org twin status must not be empty")
		}
		if seen[s] {
			t.Fatalf("duplicate: %s", s)
		}
		seen[s] = true
	}
}

func TestFinal_OrgTwinJSON(t *testing.T) {
	ot := OrgTwin{ID: "ot1", TenantID: "t1", Status: TwinStatusCurrent, SnapshotAt: time.Now()}
	data, _ := json.Marshal(ot)
	var ot2 OrgTwin
	json.Unmarshal(data, &ot2)
	if ot2.ID != "ot1" || ot2.Status != TwinStatusCurrent {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_PolicyRuleJSON(t *testing.T) {
	pr := PolicyRule{ID: "r1", Name: "no-delete", Expression: "action != 'delete'", Enabled: true}
	data, _ := json.Marshal(pr)
	var pr2 PolicyRule
	json.Unmarshal(data, &pr2)
	if !pr2.Enabled {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_RoleSnapshotJSON(t *testing.T) {
	rs := RoleSnapshot{RoleID: "r1", Name: "Admin", Permissions: []string{"*"}, ActorCount: 5}
	data, _ := json.Marshal(rs)
	var rs2 RoleSnapshot
	json.Unmarshal(data, &rs2)
	if rs2.ActorCount != 5 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_BudgetSnapshotJSON(t *testing.T) {
	bs := BudgetSnapshot{BudgetID: "b1", Name: "compute", AllocatedCents: 10000, SpentCents: 3000, Currency: "USD"}
	data, _ := json.Marshal(bs)
	var bs2 BudgetSnapshot
	json.Unmarshal(data, &bs2)
	if bs2.AllocatedCents != 10000 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_AuthoritySnapshotJSON(t *testing.T) {
	as := AuthoritySnapshot{PrincipalID: "p1", Role: "admin", Delegates: []string{"a1", "a2"}}
	data, _ := json.Marshal(as)
	var as2 AuthoritySnapshot
	json.Unmarshal(data, &as2)
	if len(as2.Delegates) != 2 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_BudgetSimulationJSON(t *testing.T) {
	bs := BudgetSimulation{SimID: "bs1", Scenario: "GROWTH"}
	data, _ := json.Marshal(bs)
	var bs2 BudgetSimulation
	json.Unmarshal(data, &bs2)
	if bs2.Scenario != "GROWTH" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_BudgetAdjustmentJSON(t *testing.T) {
	ba := BudgetAdjustment{Category: "compute", ChangeType: "INCREASE", AmountCents: 5000}
	data, _ := json.Marshal(ba)
	var ba2 BudgetAdjustment
	json.Unmarshal(data, &ba2)
	if ba2.AmountCents != 5000 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_BudgetSimResultJSON(t *testing.T) {
	bsr := BudgetSimResult{ProjectedSpendCents: 50000, OverBudget: false, RiskLevel: "LOW"}
	data, _ := json.Marshal(bsr)
	var bsr2 BudgetSimResult
	json.Unmarshal(data, &bsr2)
	if bsr2.RiskLevel != "LOW" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_StressScenarioJSON(t *testing.T) {
	ss := StressScenario{ScenarioID: "ss1", Type: "LOAD", Target: "guardian", Intensity: 8}
	data, _ := json.Marshal(ss)
	var ss2 StressScenario
	json.Unmarshal(data, &ss2)
	if ss2.Intensity != 8 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_SimulationResultJSON(t *testing.T) {
	sr := SimulationResult{ScenarioID: "s1", Action: "test", Decision: "ALLOW", Reason: "ok"}
	data, _ := json.Marshal(sr)
	var sr2 SimulationResult
	json.Unmarshal(data, &sr2)
	if sr2.Decision != "ALLOW" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_WhatIfResultJSON(t *testing.T) {
	wir := WhatIfResult{ProposedChange: "add policy", FlippedDecisions: 2}
	data, _ := json.Marshal(wir)
	var wir2 WhatIfResult
	json.Unmarshal(data, &wir2)
	if wir2.FlippedDecisions != 2 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_CostProjectionJSON(t *testing.T) {
	cp := CostProjection{ScenarioID: "s1", ProjectedCents: 10000, Currency: "USD"}
	data, _ := json.Marshal(cp)
	var cp2 CostProjection
	json.Unmarshal(data, &cp2)
	if cp2.ProjectedCents != 10000 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ComplianceImpactJSON(t *testing.T) {
	ci := ComplianceImpact{ChangeDescription: "new policy", AffectedPolicies: []string{"p1", "p2", "p3"}}
	data, _ := json.Marshal(ci)
	var ci2 ComplianceImpact
	json.Unmarshal(data, &ci2)
	if len(ci2.AffectedPolicies) != 3 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DriftReportJSON(t *testing.T) {
	dr := DriftReport{TwinID: "t1", DriftedPolicies: []string{"p1"}}
	data, _ := json.Marshal(dr)
	var dr2 DriftReport
	json.Unmarshal(data, &dr2)
	if dr2.TwinID != "t1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_RolloutPlanJSON(t *testing.T) {
	rp := RolloutPlan{ID: "rp1", Name: "gradual"}
	data, _ := json.Marshal(rp)
	var rp2 RolloutPlan
	json.Unmarshal(data, &rp2)
	if rp2.ID != "rp1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_FailureScenarioJSON(t *testing.T) {
	fs := FailureScenario{ID: "fs1", Name: "network failure"}
	data, _ := json.Marshal(fs)
	var fs2 FailureScenario
	json.Unmarshal(data, &fs2)
	if fs2.Name != "network failure" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_RunnerNew(t *testing.T) {
	r := NewRunner()
	if r == nil {
		t.Fatal("runner should not be nil")
	}
}

func TestFinal_NewOrgTwin(t *testing.T) {
	ot := NewOrgTwin("ot1", "t1", []PolicyRule{{ID: "r1", Enabled: true}}, nil, nil, nil)
	if ot == nil || ot.ContentHash == "" {
		t.Fatal("new org twin should have content hash")
	}
}

func TestFinal_NewOrgTwinDeterminism(t *testing.T) {
	ot1 := NewOrgTwin("ot1", "t1", []PolicyRule{{ID: "r1"}}, nil, nil, nil)
	ot2 := NewOrgTwin("ot1", "t1", []PolicyRule{{ID: "r1"}}, nil, nil, nil)
	if ot1.ContentHash != ot2.ContentHash {
		t.Fatal("content hash should be deterministic")
	}
}

func TestFinal_ConcurrentNewOrgTwin(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			NewOrgTwin("ot1", "t1", nil, nil, nil, nil)
		}()
	}
	wg.Wait()
}

func TestFinal_StaffEntryJSON(t *testing.T) {
	se := StaffEntry{ActorType: "HUMAN", Role: "engineer", Count: 10}
	data, _ := json.Marshal(se)
	var se2 StaffEntry
	json.Unmarshal(data, &se2)
	if se2.Count != 10 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_SafetyCheckJSON(t *testing.T) {
	sc := SafetyCheck{CheckID: "c1", Type: "PRE_FLIGHT", Condition: "true"}
	data, _ := json.Marshal(sc)
	var sc2 SafetyCheck
	json.Unmarshal(data, &sc2)
	if sc2.Type != "PRE_FLIGHT" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_OrgTwinDeltaJSON(t *testing.T) {
	otd := OrgTwinDelta{BaseID: "b1", CompareID: "c1", AddedPolicies: []string{"p1", "p2"}}
	data, _ := json.Marshal(otd)
	var otd2 OrgTwinDelta
	json.Unmarshal(data, &otd2)
	if len(otd2.AddedPolicies) != 2 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_StressTestRunnerJSON(t *testing.T) {
	str := StressTestRunner{TestID: "st1", Name: "load test", Concurrency: 100}
	data, _ := json.Marshal(str)
	var str2 StressTestRunner
	json.Unmarshal(data, &str2)
	if str2.Concurrency != 100 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_RehearsalStepJSON(t *testing.T) {
	rs := RehearsalStep{StepID: "rs1", Domain: "PHYSICAL", Description: "move-arm"}
	data, _ := json.Marshal(rs)
	var rs2 RehearsalStep
	json.Unmarshal(data, &rs2)
	if rs2.Domain != "PHYSICAL" {
		t.Fatal("round-trip mismatch")
	}
}
