package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestWorkstationImportAndView(t *testing.T) {
	root := kernelRepoRoot(t)
	fixture := filepath.Join(root, "fixtures", "workstation", "denied-network")
	outFile := filepath.Join(t.TempDir(), "workstation-receipt.json")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "workstation", "import", "--artifacts", fixture, "--out", outFile}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("import exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Agent Run Receipt") {
		t.Fatalf("import summary missing header: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "workstation", "view", "--receipt", outFile}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("view exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "signature:     true") {
		t.Fatalf("view summary missing valid signature: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "denied:        1") {
		t.Fatalf("view summary missing denied count: %s", stdout.String())
	}
}

func TestWorkstationRemainingPhaseCommands(t *testing.T) {
	root := kernelRepoRoot(t)
	fixtureRoot := filepath.Join(root, "fixtures", "workstation")
	tmp := t.TempDir()

	var stdout, stderr bytes.Buffer
	networkReceipt := filepath.Join(tmp, "network-deny.json")
	code := Run([]string{
		"helm-ai-kernel", "workstation", "enforce",
		"--class", "network",
		"--target", "https://forbidden.example",
		"--out", networkReceipt,
	}, &stdout, &stderr)
	if code != 126 {
		t.Fatalf("network enforce exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	decision := readDecisionReceipt(t, networkReceipt)
	if decision.Verdict != contracts.WorkstationVerdictDeny || decision.ReasonCode != "EGRESS_ALLOWLIST_EMPTY" {
		t.Fatalf("network decision = %s/%s, want DENY/EGRESS_ALLOWLIST_EMPTY", decision.Verdict, decision.ReasonCode)
	}

	stdout.Reset()
	stderr.Reset()
	receiptDir := filepath.Join(tmp, "decision-receipts")
	code = Run([]string{
		"helm-ai-kernel", "workstation", "decide",
		"--class", "network",
		"--target", "https://api.github.com/repos/Mindburn-Labs/helm",
		"--policy-profile", filepath.Join(fixtureRoot, "policies", "observe_draft.v1.allow.json"),
		"--receipt-dir", receiptDir,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("allowed network decide exit = %d stderr = %s", code, stderr.String())
	}
	receipts, err := filepath.Glob(filepath.Join(receiptDir, "*.json"))
	if err != nil || len(receipts) != 1 {
		t.Fatalf("receipt dir files = %v err=%v, want one", receipts, err)
	}
	decision = readDecisionReceipt(t, receipts[0])
	if decision.Verdict != contracts.WorkstationVerdictAllow {
		t.Fatalf("allowed network verdict = %s, want ALLOW", decision.Verdict)
	}

	stdout.Reset()
	stderr.Reset()
	memoryReceipt := filepath.Join(tmp, "memory-deny.json")
	code = Run([]string{
		"helm-ai-kernel", "workstation", "enforce",
		"--class", "memory",
		"--target", "memory://repo-rule",
		"--out", memoryReceipt,
	}, &stdout, &stderr)
	if code != 126 {
		t.Fatalf("memory enforce exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	decision = readDecisionReceipt(t, memoryReceipt)
	if decision.Verdict != contracts.WorkstationVerdictDeny || decision.ReasonCode != "OPERATE_PERMISSIONS_EMPTY" {
		t.Fatalf("memory decision = %s/%s, want DENY/OPERATE_PERMISSIONS_EMPTY", decision.Verdict, decision.ReasonCode)
	}

	stdout.Reset()
	stderr.Reset()
	draftReceipt := filepath.Join(tmp, "draft-allow.json")
	code = Run([]string{
		"helm-ai-kernel", "workstation", "decide",
		"--class", "file",
		"--target", "docs/example.md",
		"--out", draftReceipt,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("draft decide exit = %d stderr = %s", code, stderr.String())
	}
	decision = readDecisionReceipt(t, draftReceipt)
	if decision.Verdict != contracts.WorkstationVerdictAllow {
		t.Fatalf("draft decision = %s, want ALLOW", decision.Verdict)
	}

	stdout.Reset()
	stderr.Reset()
	importOut := filepath.Join(tmp, "denied-memory-import.json")
	code = Run([]string{
		"helm-ai-kernel", "workstation", "import",
		"--artifacts", filepath.Join(fixtureRoot, "denied-memory"),
		"--out", importOut,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("import exit = %d stderr = %s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "workstation", "memory", "--input", tmp}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("memory view exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Memory review queue: 1") {
		t.Fatalf("memory view missing queue: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	packDir := filepath.Join(tmp, "sample-evidencepack")
	code = Run([]string{"helm-ai-kernel", "workstation", "evidence", "--receipt", importOut, "--out", packDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("evidence exit = %d stderr = %s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(packDir, "00_INDEX.json")); err != nil {
		t.Fatalf("sample EvidencePack index missing: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "workstation", "certify", "--fixtures", fixtureRoot, "--mode", "high-risk-effect-capable"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("certify exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "passed:    true") {
		t.Fatalf("certify output missing pass: %s", stdout.String())
	}
}

func TestWorkstationCLIRejectsArgvSigningSeed(t *testing.T) {
	root := kernelRepoRoot(t)
	fixture := filepath.Join(root, "fixtures", "workstation", "denied-network")

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "workstation", "import",
		"--artifacts", fixture,
		"--signing-seed-hex", strings.Repeat("0", 64),
		"--json",
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("unsafe seed flag exit = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--signing-seed-hex is disabled") {
		t.Fatalf("stderr missing unsafe seed error: %s", stderr.String())
	}
}

func TestWorkstationCLIAcceptsSigningSeedFile(t *testing.T) {
	root := kernelRepoRoot(t)
	fixture := filepath.Join(root, "fixtures", "workstation", "denied-network")
	seedFile := filepath.Join(t.TempDir(), "receipt.seed")
	if err := os.WriteFile(seedFile, []byte(strings.Repeat("1", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "workstation", "import",
		"--artifacts", fixture,
		"--signing-seed-file", seedFile,
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("seed-file import exit = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "signer_key_id") {
		t.Fatalf("json output missing signer key: %s", stdout.String())
	}
}

func TestWorkstationEnforceRefusesObserveModeCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	marker := filepath.Join(t.TempDir(), "observe-mode-executed")
	code := Run([]string{
		"helm-ai-kernel", "workstation", "enforce",
		"--class", "shell",
		"--", "/usr/bin/touch", marker,
	}, &stdout, &stderr)
	if code != 126 {
		t.Fatalf("observe command exit = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("observe-mode command executed or marker stat failed: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "operate-mode ALLOW") {
		t.Fatalf("stderr missing operate-mode refusal: %s", stderr.String())
	}
}

func TestWorkstationCaptureCommands(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	artifacts := filepath.Join(tmp, "artifacts")
	out := filepath.Join(tmp, "capture-receipt.json")

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "workstation", "capture", "start",
		"--surface", "codex",
		"--workspace", workspace,
		"--goal", "Capture a local run",
		"--started-at", "2026-05-20T15:00:00Z",
		"--out", artifacts,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("capture start exit = %d stderr = %s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(artifacts, "run.manifest.json")); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{
		"helm-ai-kernel", "workstation", "capture", "finish",
		"--artifacts", artifacts,
		"--validation-command", "printf ok",
		"--completed-at", "2026-05-20T15:01:00Z",
		"--out", out,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("capture finish exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "Agent Run Receipt") {
		t.Fatalf("capture finish missing summary: %s", stdout.String())
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("capture receipt missing: %v", err)
	}
}

func kernelRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func readDecisionReceipt(t *testing.T, path string) contracts.WorkstationPolicyDecisionReceipt {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt contracts.WorkstationPolicyDecisionReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}
