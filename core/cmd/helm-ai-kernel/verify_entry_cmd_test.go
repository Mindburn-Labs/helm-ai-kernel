package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
)

func writeTestManifest(t *testing.T, dir string) string {
	t.Helper()
	b := evidencepack.NewBuilder("pack-cli-min512", "did:helm:agent", "intent-1", "sha256:"+rep("a", 64)).
		WithCreatedAt(time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC))
	if err := b.AddReceipt("decision-001", map[string]any{"verdict": "DENY", "receipt_id": "r1"}); err != nil {
		t.Fatal(err)
	}
	_ = b.AddPolicyDecision("gate", map[string]any{"outcome": "deny"})
	_ = b.AddToolTranscript("tool-1", map[string]any{"status": "failure"})
	m, _, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(m, "", "  ")
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func rep(s string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = s[0]
	}
	return string(out)
}

func TestCLI_ProveAndVerifyEntry_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeTestManifest(t, dir)
	proofPath := filepath.Join(dir, "entry.proof.json")

	// Generate.
	var stdout, stderr bytes.Buffer
	rc := runEvidenceProveEntry([]string{"--manifest", manifestPath, "--entry", "receipts/decision-001.json", "--out", proofPath}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("prove-entry rc=%d stderr=%s", rc, stderr.String())
	}

	// Verify (routed through the top-level verify command to exercise dispatch).
	stdout.Reset()
	stderr.Reset()
	rc = runVerifyCmd([]string{"--entry", "receipts/decision-001.json", "--proof", proofPath, "--json"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("verify rc=%d stderr=%s out=%s", rc, stderr.String(), stdout.String())
	}
	var res entryVerifyResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("decode result: %v (%s)", err, stdout.String())
	}
	if !res.Verified {
		t.Fatalf("expected verified, got %+v", res)
	}
}

// NEGATIVE: asking for a different entry than the proof binds to FAILS.
func TestCLI_VerifyEntry_WrongEntryName(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeTestManifest(t, dir)
	proofPath := filepath.Join(dir, "entry.proof.json")

	var sink bytes.Buffer
	if rc := runEvidenceProveEntry([]string{"--manifest", manifestPath, "--entry", "receipts/decision-001.json", "--out", proofPath}, &sink, &sink); rc != 0 {
		t.Fatalf("prove-entry failed: %s", sink.String())
	}

	var stdout, stderr bytes.Buffer
	rc := runVerifyEntryCmd([]string{"--entry", "policy/gate.json", "--proof", proofPath}, &stdout, &stderr)
	if rc != 1 {
		t.Fatalf("expected rc=1 for wrong entry name, got %d (%s)", rc, stdout.String())
	}
}

// NEGATIVE: a tampered proof file FAILS through the CLI.
func TestCLI_VerifyEntry_TamperedProofFails(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeTestManifest(t, dir)
	proofPath := filepath.Join(dir, "entry.proof.json")

	var sink bytes.Buffer
	if rc := runEvidenceProveEntry([]string{"--manifest", manifestPath, "--entry", "receipts/decision-001.json", "--out", proofPath}, &sink, &sink); rc != 0 {
		t.Fatalf("prove-entry failed: %s", sink.String())
	}

	raw, _ := os.ReadFile(proofPath)
	var proof evidencepack.InclusionProof
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	proof.Entry.Size = proof.Entry.Size + 1 // tamper
	tampered, _ := json.MarshalIndent(proof, "", "  ")
	if err := os.WriteFile(proofPath, tampered, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	rc := runVerifyEntryCmd([]string{"--proof", proofPath}, &stdout, &stderr)
	if rc != 1 {
		t.Fatalf("expected rc=1 for tampered proof, got %d (%s)", rc, stdout.String())
	}
}

func TestCLI_VerifyEntry_MissingProofFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if rc := runVerifyEntryCmd([]string{"--entry", "receipts/x.json"}, &stdout, &stderr); rc != 2 {
		t.Fatalf("expected rc=2 when --proof missing, got %d", rc)
	}
}
