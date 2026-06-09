package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunMCPProofProducesNoDispatchEvidencePack(t *testing.T) {
	outRoot := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := runMCPProof([]string{
		"--scenario", "all",
		"--out", outRoot,
		"--run-id", "mcp-proof-test",
		"--at", "2026-06-09T00:00:00Z",
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runMCPProof code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}

	var summary mcpProofSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode summary: %v\n%s", err, stdout.String())
	}
	if summary.RunID != "mcp_proof_test" {
		t.Fatalf("run id = %q", summary.RunID)
	}
	if !summary.OfflineVerified {
		t.Fatalf("offline verifier did not pass: %#v", summary)
	}
	if len(summary.Scenarios) != 7 {
		t.Fatalf("scenario count = %d, want 7", len(summary.Scenarios))
	}
	if _, err := os.Stat(filepath.Join(summary.EvidencePackRef, "07_ATTESTATIONS", "evidence_pack.sig")); err != nil {
		t.Fatalf("sealed EvidencePack missing: %v", err)
	}
	if _, err := os.Stat(summary.EvidencePackArchive); err != nil {
		t.Fatalf("EvidencePack archive missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outRoot, "mcp_proof_test", "verification_report.json")); err != nil {
		t.Fatalf("verification report missing: %v", err)
	}

	reasons := map[string]bool{}
	for _, result := range summary.Scenarios {
		if result.Dispatched {
			t.Fatalf("%s dispatched unexpectedly", result.ScenarioID)
		}
		if result.Verdict == "ALLOW" {
			t.Fatalf("%s allowed unexpectedly: %#v", result.ScenarioID, result)
		}
		if result.ReceiptRef == "" || result.ReceiptHash == "" {
			t.Fatalf("%s missing receipt ref/hash: %#v", result.ScenarioID, result)
		}
		reasons[result.Reason] = true

		var receipt map[string]any
		data, err := os.ReadFile(filepath.Join(summary.EvidencePackRef, filepath.FromSlash(result.ReceiptRef)))
		if err != nil {
			t.Fatalf("read receipt for %s: %v", result.ScenarioID, err)
		}
		if err := json.Unmarshal(data, &receipt); err != nil {
			t.Fatalf("decode receipt for %s: %v", result.ScenarioID, err)
		}
		if receipt["signature"] == "" || receipt["decision_hash"] == "" {
			t.Fatalf("receipt for %s is not signed/decision-bound: %#v", result.ScenarioID, receipt)
		}
		if metadata, ok := receipt["metadata"].(map[string]any); !ok || metadata["dispatched"] != false {
			t.Fatalf("receipt for %s does not bind dispatched=false: %#v", result.ScenarioID, receipt["metadata"])
		}
	}

	for _, reason := range []string{
		"ERR_MCP_SERVER_QUARANTINED",
		"ERR_MCP_APPROVAL_RECEIPT_REQUIRED",
		"ERR_MCP_LAUNCH_SCOPE_MISMATCH",
		"ERR_MCP_TOOL_QUARANTINED",
		"ERR_MCP_SCHEMA_DRIFT",
		"ERR_MCP_REPLAY_REORDERING_ATTEMPT",
	} {
		if !reasons[reason] {
			t.Fatalf("missing proof reason %s in %#v", reason, reasons)
		}
	}
}

func TestRunMCPProofSupportsFocusedScenario(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPProof([]string{
		"--scenario", "schema_drift",
		"--out", t.TempDir(),
		"--run-id", "schema-drift",
		"--at", "2026-06-09T00:00:00Z",
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runMCPProof code=%d stderr=%s", code, stderr.String())
	}
	var summary mcpProofSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if len(summary.Scenarios) != 1 || summary.Scenarios[0].Reason != "ERR_MCP_SCHEMA_DRIFT" {
		t.Fatalf("focused scenario summary = %#v", summary.Scenarios)
	}
}

func TestRunMCPProofRejectsUnknownScenario(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPProof([]string{"--scenario", "not-real", "--out", t.TempDir()}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "unknown --scenario") {
		t.Fatalf("missing unknown scenario error: %s", stderr.String())
	}
}

func TestRunMCPCmdHelpIncludesProof(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPCmd([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "proof") {
		t.Fatalf("mcp help does not include proof:\n%s", stdout.String())
	}
}
