package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func writePlanFixture(t *testing.T, dir string, effectType string) string {
	t.Helper()
	plan := contracts.PlanSpec{
		ID:      "plan-test",
		Version: "2.0.0",
		DAG: &contracts.DAG{
			Nodes: []contracts.PlanStep{{
				ID:                 "step-1",
				EffectType:         effectType,
				Description:        "test step",
				AcceptanceCriteria: []string{"done"},
			}},
		},
	}
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPlanEvaluateRequiresPolicyUnlessDryRun(t *testing.T) {
	dir := t.TempDir()
	planPath := writePlanFixture(t, dir, "READ")
	var stdout, stderr bytes.Buffer

	code := runPlanEvaluate([]string{"--plan", planPath}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected config error, got %d", code)
	}
	if !strings.Contains(stderr.String(), "--policy is required") {
		t.Fatalf("expected policy error, got %q", stderr.String())
	}
}

func TestPlanEvaluateDryRunUsesExplicitReason(t *testing.T) {
	dir := t.TempDir()
	planPath := writePlanFixture(t, dir, "READ")
	var stdout, stderr bytes.Buffer

	code := runPlanEvaluate([]string{"--plan", planPath, "--dry-run"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected success, got %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "CLI_DRY_RUN") {
		t.Fatalf("expected dry-run reason, got %s", stdout.String())
	}
}

func TestPlanEvaluateGuardianPolicyAllowsAndDenies(t *testing.T) {
	dir := t.TempDir()
	planPath := writePlanFixture(t, dir, "READ")
	allowPolicy := filepath.Join(dir, "allow.cel")
	denyPolicy := filepath.Join(dir, "deny.cel")
	if err := os.WriteFile(allowPolicy, []byte(`input.action == "READ"`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(denyPolicy, []byte(`input.action == "WRITE"`), 0644); err != nil {
		t.Fatal(err)
	}

	var allowOut, allowErr bytes.Buffer
	if code := runPlanEvaluate([]string{"--plan", planPath, "--policy", allowPolicy}, &allowOut, &allowErr); code != 0 {
		t.Fatalf("expected allow success, got %d: %s", code, allowErr.String())
	}
	if strings.Contains(allowOut.String(), "CLI_DRY_RUN") {
		t.Fatalf("guardian path must not emit dry-run reason: %s", allowOut.String())
	}

	var denyOut, denyErr bytes.Buffer
	if code := runPlanEvaluate([]string{"--plan", planPath, "--policy", denyPolicy}, &denyOut, &denyErr); code != 1 {
		t.Fatalf("expected deny exit 1, got %d: %s", code, denyErr.String())
	}
	if !strings.Contains(denyOut.String(), "MISSING_REQUIREMENT") {
		t.Fatalf("expected Guardian deny reason, got %s", denyOut.String())
	}
}
