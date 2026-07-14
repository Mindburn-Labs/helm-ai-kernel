package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func TestHookPreToolDeniesDestructiveBashAndWritesReceipt(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	payload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/helm-demo"},"session_id":"s1","cwd":"/repo"}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
	}
	var out hookDecisionOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("hook output JSON: %v\n%s", err, stdout.String())
	}
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("decision = %q, want deny", out.HookSpecificOutput.PermissionDecision)
	}
	receipts := globReceipts(t, tmp)
	if len(receipts) != 1 {
		t.Fatalf("receipts = %v, want one", receipts)
	}
	receipt, err := workstation.LoadDecisionReceipt(receipts[0])
	if err != nil {
		t.Fatalf("load receipt: %v", err)
	}
	if receipt.Verdict != contracts.WorkstationVerdictDeny || receipt.ReasonCode != "OPERATE_PERMISSIONS_EMPTY" {
		t.Fatalf("receipt = %s/%s, want DENY/OPERATE_PERMISSIONS_EMPTY", receipt.Verdict, receipt.ReasonCode)
	}
	if ok, err := workstation.VerifyDecisionReceiptSignature(receipt); err != nil || !ok {
		t.Fatalf("receipt signature ok=%v err=%v", ok, err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "workstation", "verify-decision", "--receipt", receipts[0]}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify-decision exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "signature: true") {
		t.Fatalf("verify-decision output missing signature=true: %s", stdout.String())
	}

	raw, err := os.ReadFile(receipts[0])
	if err != nil {
		t.Fatalf("read receipt for tamper test: %v", err)
	}
	tampered := filepath.Join(tmp, "tampered-decision.json")
	if err := os.WriteFile(tampered, []byte(strings.Replace(string(raw), "rm -rf /tmp/helm-demo", "rm -rf /tmp/helm-demo2", 1)), 0o600); err != nil {
		t.Fatalf("write tampered receipt: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "workstation", "verify-decision", "--receipt", tampered}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("tampered verify-decision exit = %d, want 1 stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "signature: false") {
		t.Fatalf("tampered verify-decision output missing signature=false: %s", stdout.String())
	}
}

func TestHookPreToolAllowsSafeBashWithoutApprovalOutput(t *testing.T) {
	tmp := t.TempDir()
	payload := `{"tool_name":"Bash","tool_input":{"command":"git status --short"}}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "codex", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("safe bash should not emit approval output, got %s", stdout.String())
	}
	if receipts := globReceipts(t, tmp); len(receipts) != 0 {
		t.Fatalf("safe bash wrote receipts: %v", receipts)
	}
}

func TestHookPreToolDeniesCodexMCPButSkipsHelmSelfMCP(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	payload := `{"toolName":"mcp__filesystem__write_file","toolInput":{"path":"/tmp/x"}}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "codex", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("MCP call should be denied, output = %s", stdout.String())
	}
	if receipts := globReceipts(t, tmp); len(receipts) != 1 {
		t.Fatalf("MCP deny receipts = %v, want one", receipts)
	}

	stdout.Reset()
	stderr.Reset()
	self := `{"toolName":"mcp__helm-ai-kernel-governance__decide","toolInput":{}}`
	code = runHookPreToolCmd([]string{"--client", "codex", "--data-dir", tmp}, strings.NewReader(self), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("self hook exit = %d stderr = %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("self HELM MCP call should not emit output, got %s", stdout.String())
	}
	if receipts := globReceipts(t, tmp); len(receipts) != 1 {
		t.Fatalf("self HELM MCP call wrote receipt, receipts = %v", receipts)
	}

	stdout.Reset()
	stderr.Reset()
	spoofed := `{"toolName":"mcp__evil-helm-ai-kernel-governance__write","toolInput":{"path":"/tmp/x"}}`
	code = runHookPreToolCmd([]string{"--client", "codex", "--data-dir", tmp}, strings.NewReader(spoofed), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("substring-spoofed MCP server escaped hook: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if receipts := globReceipts(t, tmp); len(receipts) != 2 {
		t.Fatalf("spoofed MCP deny did not persist a receipt, receipts = %v", receipts)
	}
}

func TestHookPreToolFailsClosedWhenReceiptPathIsSymlinked(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	external := filepath.Join(t.TempDir(), "external")
	if err := os.MkdirAll(external, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(tmp, "receipts")); err != nil {
		t.Fatal(err)
	}
	payload := `{"tool_name":"Write","tool_input":{"file_path":".env"}}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "codex", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) || !strings.Contains(stdout.String(), "could not be persisted") {
		t.Fatalf("symlinked hook receipt path did not fail closed: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	entries, err := os.ReadDir(external)
	if err != nil || len(entries) != 0 {
		t.Fatalf("hook receipt escaped through symlink: entries=%v err=%v", entries, err)
	}
}

func TestWriteHookDecisionReceiptRejectsSymlinkedFinalPath(t *testing.T) {
	tmp := t.TempDir()
	receipt := &contracts.WorkstationPolicyDecisionReceipt{DecisionID: "wpd_test"}
	receiptDir := filepath.Join(tmp, "receipts", "hooks")
	if err := os.MkdirAll(receiptDir, 0o700); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "external.json")
	if err := os.WriteFile(external, []byte("do-not-touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(receiptDir, receipt.DecisionID+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err := writeHookDecisionReceipt(tmp, receipt); err == nil {
		t.Fatal("symlinked final hook receipt path was accepted")
	}
	got, err := os.ReadFile(external)
	if err != nil || string(got) != "do-not-touch" {
		t.Fatalf("symlinked final hook receipt target changed: got=%q err=%v", got, err)
	}
}

func TestHookPreToolDeniesSensitiveWrite(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	payload := `{"tool_name":"Write","tool_input":{"file_path":".env"}}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("sensitive write should be denied, output = %s", stdout.String())
	}
}

func TestHookPreToolFailsClosedForMalformedOrUnnamedPayload(t *testing.T) {
	tmp := t.TempDir()
	for _, payload := range []string{"not-json", `{"tool_input":{"path":"/tmp/x"}}`} {
		t.Run(payload, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runHookPreToolCmd([]string{"--client", "codex", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
			if code != 0 || !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) || !strings.Contains(stdout.String(), "could not decode") {
				t.Fatalf("malformed hook payload did not produce structured deny: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestHookPreToolDeniesCodexApplyPatchSensitiveWrite(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	payload := `{"toolName":"apply_patch","toolInput":{"command":"*** Begin Patch\n*** Update File: .env\n+SECRET=value\n*** End Patch\n"}}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "codex", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("apply_patch sensitive write should be denied, output = %s", stdout.String())
	}
	receipts := globReceipts(t, tmp)
	if len(receipts) != 1 {
		t.Fatalf("receipts = %v, want one", receipts)
	}
	receipt, err := workstation.LoadDecisionReceipt(receipts[0])
	if err != nil {
		t.Fatalf("load receipt: %v", err)
	}
	if receipt.Request.Target != ".env" {
		t.Fatalf("receipt target = %q, want .env", receipt.Request.Target)
	}
}

func restoreHookClock(t *testing.T) {
	t.Helper()
	old := hookNow
	hookNow = func() time.Time { return time.Unix(0, 0).UTC() }
	t.Cleanup(func() { hookNow = old })
}

func globReceipts(t *testing.T, dataDir string) []string {
	t.Helper()
	receipts, err := filepath.Glob(filepath.Join(dataDir, "receipts", "hooks", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, receipt := range receipts {
		if _, err := os.Stat(receipt); err != nil {
			t.Fatalf("stat receipt %s: %v", receipt, err)
		}
	}
	return receipts
}
