package capability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadRollbackDir_Valid(t *testing.T) {
	reg := testRegistry(t)
	store, err := LoadRollbackDir(filepath.Join("testdata", "plans"), reg)
	if err != nil {
		t.Fatalf("LoadRollbackDir: %v", err)
	}
	if store.Len() != 2 {
		t.Fatalf("expected 2 plans, got %d", store.Len())
	}
	entry := store.ResolvePlan("plans/gui-navigate-back.v1")
	if entry == nil {
		t.Fatal("expected navigate-back plan to resolve")
	}
	if entry.Plan.Strategy != StrategyCompensatingAction {
		t.Fatalf("unexpected strategy: %s", entry.Plan.Strategy)
	}
	if entry.Hash == "" || len(entry.Hash) != len("sha256:")+64 {
		t.Fatalf("plan hash malformed: %q", entry.Hash)
	}
	if store.ResolvePlan("plans/nonexistent.v1") != nil {
		t.Fatal("unknown plan must not resolve")
	}
	if entry.Plan.Expired(time.Now()) {
		t.Fatal("plan without guarantee_expiry must never expire")
	}
}

func TestLoadRollbackDir_RejectsUnregisteredStepAction(t *testing.T) {
	reg := testRegistry(t)
	if _, err := LoadRollbackDir(filepath.Join("testdata", "plans-invalid"), reg); err == nil {
		t.Fatal("plan with unregistered step action_ref must fail load (fail closed)")
	}
}

func TestLoadRollbackDir_Errors(t *testing.T) {
	reg := testRegistry(t)
	if _, err := LoadRollbackDir(filepath.Join("testdata", "does-not-exist"), reg); err == nil {
		t.Fatal("expected error for missing directory")
	}
	if _, err := LoadRollbackDir(t.TempDir(), reg); err == nil {
		t.Fatal("expected error for empty directory")
	}
}

func TestRollbackPlan_Validate(t *testing.T) {
	reg := testRegistry(t)
	valid := func() RollbackPlan {
		return RollbackPlan{
			SchemaVersion: RollbackPlanSchemaVersion,
			PlanID:        "plans/test.v1",
			Strategy:      StrategyExactUndo,
			AppliesTo:     RollbackAppliesTo{CapabilityID: "helm.cap.gui.gelab.tap"},
			Steps:         []RollbackStep{{Order: 1, ActionRef: "helm.cap.gui.gelab.tap", Description: "undo"}},
			Verification:  RollbackVerification{Method: VerifyReceiptPairing},
		}
	}
	p := valid()
	if err := p.Validate(reg); err != nil {
		t.Fatalf("valid plan rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*RollbackPlan)
	}{
		{"bad schema", func(p *RollbackPlan) { p.SchemaVersion = "v0" }},
		{"missing plan id", func(p *RollbackPlan) { p.PlanID = "" }},
		{"bad strategy", func(p *RollbackPlan) { p.Strategy = "wishful_thinking" }},
		{"missing applies to", func(p *RollbackPlan) { p.AppliesTo = RollbackAppliesTo{} }},
		{"unknown applies to capability", func(p *RollbackPlan) { p.AppliesTo.CapabilityID = "helm.cap.nope.nope" }},
		{"no steps", func(p *RollbackPlan) { p.Steps = nil }},
		{"zero order", func(p *RollbackPlan) { p.Steps[0].Order = 0 }},
		{"duplicate order", func(p *RollbackPlan) {
			p.Steps = append(p.Steps, RollbackStep{Order: 1, ActionRef: "helm.cap.fs.read", Description: "dup"})
		}},
		{"missing action ref", func(p *RollbackPlan) { p.Steps[0].ActionRef = "" }},
		{"unregistered action", func(p *RollbackPlan) { p.Steps[0].ActionRef = "helm.cap.nope.nope" }},
		{"bad verification", func(p *RollbackPlan) { p.Verification.Method = "vibes" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := valid()
			tc.mutate(&p)
			if err := p.Validate(reg); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestRollbackPlan_Expired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	p := RollbackPlan{GuaranteeExpiry: &past}
	if !p.Expired(time.Now()) {
		t.Fatal("past guarantee_expiry must be expired")
	}
	p.GuaranteeExpiry = &future
	if p.Expired(time.Now()) {
		t.Fatal("future guarantee_expiry must not be expired")
	}
}

func TestLoadRollbackDir_RejectsUnknownAndTrailingJSON(t *testing.T) {
	reg := testRegistry(t)
	raw, err := os.ReadFile(filepath.Join("testdata", "plans", "navigate_back.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		body string
	}{
		{
			name: "unknown field",
			body: strings.Replace(string(raw), `"plan_id": "plans/gui-navigate-back.v1",`, `"plan_id": "plans/gui-navigate-back.v1",\n  "unexpected": true,`, 1),
		},
		{
			name: "trailing JSON value",
			body: string(raw) + "\n{}",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "plan.json"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadRollbackDir(dir, reg); err == nil {
				t.Fatal("expected strict parse rejection")
			}
		})
	}
}
