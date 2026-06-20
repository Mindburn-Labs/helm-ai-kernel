package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/financedemo"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

// TestDemoFinance_EscalatesAndSealsVerifiablePack runs the deterministic finance
// demo end to end: an above-limit payment must escalate before execution, the
// effect must be simulated, and the EvidencePack must seal and verify offline.
func TestDemoFinance_EscalatesAndSealsVerifiablePack(t *testing.T) {
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := runDemoFinance([]string{"--out", out}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("demo finance failed with code %d: stderr=%s", code, stderr.String())
	}

	report, err := verifier.VerifyBundle(out)
	if err != nil {
		t.Fatalf("VerifyBundle returned error: %v", err)
	}
	if !report.Verified {
		for _, c := range report.Checks {
			if !c.Pass {
				t.Logf("FAILED check %s: %s", c.Name, c.Reason)
			}
		}
		t.Fatalf("finance demo pack did not verify: %s", report.Summary)
	}
	if report.SealState != "valid" {
		t.Errorf("seal state = %q, want valid", report.SealState)
	}
	if report.SignatureValidCount < 1 {
		t.Errorf("signature_valid_count = %d, want >= 1", report.SignatureValidCount)
	}

	// The proofgraph must exist alongside the sealed receipts.
	if _, err := filepath.Glob(filepath.Join(out, "02_PROOFGRAPH", "receipts", "*.json")); err != nil {
		t.Fatalf("glob receipts: %v", err)
	}
}

// TestDemoFinance_JSONShowsEscalateBeforeExecute asserts the proof log records
// the ESCALATE verdict and that approval precedes a simulated execution.
func TestDemoFinance_JSONShowsEscalateBeforeExecute(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runDemoFinance([]string{"--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("demo finance --json failed with code %d: stderr=%s", code, stderr.String())
	}

	var res financedemo.ScenarioResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("demo finance --json output is not valid ScenarioResult JSON: %v", err)
	}
	if string(res.PreApprovalVerdict.Verdict) != "ESCALATE" {
		t.Errorf("pre-approval verdict should be ESCALATE, got %s", res.PreApprovalVerdict.Verdict)
	}
	if res.Ceremony == nil || string(res.Ceremony.State) != "approved" {
		t.Errorf("ceremony should be approved")
	}
	if res.ExecutionReceipt == nil || !res.ExecutionReceipt.Simulated {
		t.Errorf("execution receipt must be simulated (no real payment)")
	}
	if res.ExecutionReceipt != nil && res.ExecutionReceipt.ApprovalCeremonyHash == "" {
		t.Errorf("execution receipt must bind the approval ceremony hash")
	}
}

// TestDemoFinance_AmountBelowLimitFailsScenario confirms the demo is the
// above-limit path: an amount below the configured limit is a config error
// because the scenario asserts ESCALATE.
func TestDemoFinance_AmountBelowLimitFailsScenario(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runDemoFinance([]string{"--limit", "10000", "--amount", "500", "--json"}, &stdout, &stderr); code != 2 {
		t.Fatalf("below-limit amount should be a config error (exit 2), got %d: %s", code, stderr.String())
	}
}
