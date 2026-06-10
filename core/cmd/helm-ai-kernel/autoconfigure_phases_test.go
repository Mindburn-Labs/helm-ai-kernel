package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRunBlastRadiusBlocksAllVectors(t *testing.T) {
	inv := AutoconfigureInventory{
		ScanRoot: "/scan/root",
		MCPServers: []MCPServerEntry{
			{ConfigPath: ".mcp.json", Severity: "MEDIUM"},
		},
	}

	report, vectors, err := runBlastRadius(context.Background(), inv)
	if err != nil {
		t.Fatalf("runBlastRadius: %v", err)
	}
	if len(vectors) != 7 {
		t.Fatalf("vectors = %d, want 7", len(vectors))
	}
	if len(report.Results) != 11 {
		t.Fatalf("results = %d, want 11 (7 vectors, retry storm x5)", len(report.Results))
	}
	if !report.AllBlocked {
		t.Fatalf("AllBlocked = false; report: %+v", report)
	}
	if report.Allowed != 0 {
		t.Fatalf("Allowed = %d, want 0", report.Allowed)
	}
	for _, r := range report.Results {
		if r.DispatchAllowed {
			t.Fatalf("vector %s attempt %d is dispatchable — boundary leak", r.VectorID, r.Attempt)
		}
		if r.RecordHash == "" {
			t.Fatalf("vector %s attempt %d has unsealed record", r.VectorID, r.Attempt)
		}
		if r.ReasonCode == "" {
			t.Fatalf("vector %s attempt %d denied without reason code", r.VectorID, r.Attempt)
		}
	}
}

func TestRunBlastRadiusIsDeterministic(t *testing.T) {
	inv := AutoconfigureInventory{ScanRoot: "/scan/root"}
	a, _, err := runBlastRadius(context.Background(), inv)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	b, _, err := runBlastRadius(context.Background(), inv)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(a.Results) != len(b.Results) {
		t.Fatalf("result counts differ: %d vs %d", len(a.Results), len(b.Results))
	}
	for i := range a.Results {
		if a.Results[i] != b.Results[i] {
			t.Fatalf("result %d differs across runs:\n%+v\n%+v", i, a.Results[i], b.Results[i])
		}
	}
}

func TestBuildActivationSummaryPreconditions(t *testing.T) {
	outDir := t.TempDir()
	ceilings := filepath.Join(outDir, "ceilings.json")
	if err := os.WriteFile(ceilings, []byte(`{"max_spend_usd":100}`), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := buildActivationSummary(outDir, "constrained", ceilings); err == nil {
		t.Fatal("missing blast-radius report must block activation")
	}

	writeArtifact := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(outDir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeArtifact("blast_radius_report.json", `{"version":"blast-radius-report/v1","all_blocked":false}`)
	writeArtifact("policy.draft.json", `{"draft":true}`)
	writeArtifact("mcp_quarantine_plan.json", `{"draft":true}`)

	if _, err := buildActivationSummary(outDir, "constrained", ceilings); err == nil {
		t.Fatal("unblocked vectors must block activation")
	}

	writeArtifact("blast_radius_report.json", `{"version":"blast-radius-report/v1","all_blocked":true}`)

	if _, err := buildActivationSummary(outDir, "autonomous", ceilings); err == nil {
		t.Fatal("invalid mode must be rejected")
	}

	s1, err := buildActivationSummary(outDir, "constrained", ceilings)
	if err != nil {
		t.Fatalf("valid summary: %v", err)
	}
	if s1.PolicyHash == "" || s1.P0CeilingsHash == "" || s1.MCPApprovalsHash == "" || s1.ImpactReportHash == "" || s1.SummaryHash == "" {
		t.Fatalf("summary has empty hashes: %+v", s1)
	}
	s2, err := buildActivationSummary(outDir, "constrained", ceilings)
	if err != nil {
		t.Fatal(err)
	}
	if s1.SummaryHash != s2.SummaryHash {
		t.Fatalf("summary hash not deterministic: %s vs %s", s1.SummaryHash, s2.SummaryHash)
	}
}

func TestActivateRefusesWithoutCeilingsOrApprover(t *testing.T) {
	outDir := t.TempDir()
	if code := runAutoconfigureActivate([]string{"--out", outDir}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("activate without --ceilings: exit = %d, want 2", code)
	}

	ceilings := filepath.Join(outDir, "ceilings.json")
	if err := os.WriteFile(ceilings, []byte(`{"max_spend_usd":100}`), 0600); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"blast_radius_report.json": `{"version":"blast-radius-report/v1","all_blocked":true}`,
		"policy.draft.json":        `{"draft":true}`,
		"mcp_quarantine_plan.json": `{"draft":true}`,
	} {
		if err := os.WriteFile(filepath.Join(outDir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}

	if code := runAutoconfigureActivate([]string{"--out", outDir, "--ceilings", ceilings, "--sign"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("activate --sign without --approver: exit = %d, want 2", code)
	}

	if code := runAutoconfigureActivate([]string{"--out", outDir, "--ceilings", ceilings}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("prepared-not-activated path: exit = %d, want 0", code)
	}
	if _, err := os.Stat(filepath.Join(outDir, "activation_summary.json")); err != nil {
		t.Fatal("activation summary must be written on the prepared path")
	}
	if _, err := os.Stat(filepath.Join(outDir, "activation_attestation.json")); err == nil {
		t.Fatal("attestation must NOT exist without an explicit signature")
	}
}
