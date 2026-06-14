package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

// TestDemoPackVerifiesOffline is the permanent guard against MIN-738: a fresh
// `demo organization` run must produce a canonical, sealed EvidencePack that
// the offline verifier accepts out of the box (dev-local trust, no env vars).
func TestDemoPackVerifiesOffline(t *testing.T) {
	dir := chdirTempDir(t)

	var out bytes.Buffer
	if code := runDemoCompany([]string{"--template", "starter", "--provider", "mock"}, &out, &out); code != 0 {
		t.Fatalf("demo failed with code %d: %s", code, out.String())
	}

	packDir := filepath.Join(dir, "data", "evidence")
	report, err := verifier.VerifyBundle(packDir)
	if err != nil {
		t.Fatalf("VerifyBundle returned error: %v", err)
	}

	if !report.Verified {
		for _, c := range report.Checks {
			if !c.Pass {
				t.Logf("FAILED check %s: %s", c.Name, c.Reason)
			}
		}
		t.Fatalf("demo pack did not verify: %s", report.Summary)
	}
	if report.SealState != "valid" {
		t.Errorf("seal state = %q, want valid", report.SealState)
	}
	if report.SignatureValidCount < 1 {
		t.Errorf("signature_valid_count = %d, want >= 1", report.SignatureValidCount)
	}
}

// TestResearchLabPackVerifiesOffline mirrors TestDemoPackVerifiesOffline for
// the research-lab scenario, which prints the same Verify instruction.
func TestResearchLabPackVerifiesOffline(t *testing.T) {
	dir := chdirTempDir(t)

	var out bytes.Buffer
	if code := runDemoScenario("research-lab", []string{"--template", "starter", "--provider", "mock"}, &out, &out); code != 0 {
		t.Fatalf("research-lab demo failed with code %d: %s", code, out.String())
	}

	packDir := filepath.Join(dir, "data", "evidence")
	report, err := verifier.VerifyBundle(packDir)
	if err != nil {
		t.Fatalf("VerifyBundle returned error: %v", err)
	}
	if !report.Verified {
		for _, c := range report.Checks {
			if !c.Pass {
				t.Logf("FAILED check %s: %s", c.Name, c.Reason)
			}
		}
		t.Fatalf("research-lab pack did not verify: %s", report.Summary)
	}
	if report.SealState != "valid" {
		t.Errorf("seal state = %q, want valid", report.SealState)
	}
}
