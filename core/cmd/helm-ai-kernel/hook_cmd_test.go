package main

import (
	"bytes"
	"encoding/json"
	"errors"
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
	trustedKey, err := loadTrustedPublicKeyFile(workstationSigningPublicKeyPath(tmp))
	if err != nil {
		t.Fatalf("load hook trusted public key: %v", err)
	}
	if ok, err := workstation.VerifyDecisionReceiptWithTrustedKey(receipt, trustedKey); err != nil || !ok {
		t.Fatalf("trusted receipt verification ok=%v err=%v", ok, err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "workstation", "verify-decision", "--receipt", receipts[0], "--data-dir", tmp}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify-decision exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "integrity: true") || !strings.Contains(stdout.String(), "trusted:   true") {
		t.Fatalf("verify-decision output missing trusted integrity: %s", stdout.String())
	}

	wrongKeyFile := filepath.Join(tmp, "wrong-trusted.pub")
	if err := os.WriteFile(wrongKeyFile, []byte(strings.Repeat("f", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "workstation", "verify-decision", "--receipt", receipts[0], "--trusted-public-key-file", wrongKeyFile}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("wrong-anchor verify-decision exit = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "integrity: true") || !strings.Contains(stdout.String(), "trusted:   false") {
		t.Fatalf("wrong-anchor verify-decision output missing trust separation: %s", stdout.String())
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
	code = Run([]string{"helm-ai-kernel", "workstation", "verify-decision", "--receipt", tampered, "--data-dir", tmp}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("tampered verify-decision exit = %d, want 1 stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "integrity: false") {
		t.Fatalf("tampered verify-decision output missing integrity=false: %s", stdout.String())
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

func TestHookPreToolFailsClosedWhenLocalSigningKeyIsInsecure(t *testing.T) {
	tmp := t.TempDir()
	keyDir := filepath.Join(tmp, workstationSigningKeyDirectory)
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workstationSigningSeedPath(tmp), []byte(strings.Repeat("0", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /srv/production"}}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) || !strings.Contains(stdout.String(), "signer is unavailable") {
		t.Fatalf("hook should explicitly deny signer failure, output=%s", stdout.String())
	}
	if receipts := globReceipts(t, tmp); len(receipts) != 0 {
		t.Fatalf("signer failure must not write a fake receipt: %v", receipts)
	}
}

func TestHookPreToolProductionRequiresExplicitSigningSeedFile(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "true")
	tmp := t.TempDir()
	payload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /srv/production"}}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "local receipt signer is unavailable") {
		t.Fatalf("production hook without signer = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(tmp, workstationSigningKeyDirectory)); !os.IsNotExist(err) {
		t.Fatalf("production hook created local signing key state: %v", err)
	}

	seedFile := filepath.Join(t.TempDir(), "hook.seed")
	if err := os.WriteFile(seedFile, []byte(strings.Repeat("2", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp, "--signing-seed-file", seedFile}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("production hook with explicit signer = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if receipts := globReceipts(t, tmp); len(receipts) != 1 {
		t.Fatalf("explicit production signer receipts = %v, want one", receipts)
	}
	if _, err := os.Stat(workstationSigningSeedPath(tmp)); !os.IsNotExist(err) {
		t.Fatalf("production hook created fallback seed: %v", err)
	}
}

func TestHookPreToolFailsClosedWhenReceiptCannotPersist(t *testing.T) {
	tmp := t.TempDir()
	if _, err := ensureLocalWorkstationSigningSeed(tmp); err != nil {
		t.Fatalf("prepare local signing key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "receipts"), []byte("not a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /srv/production"}}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) || !strings.Contains(stdout.String(), "receipt persistence is unavailable") {
		t.Fatalf("hook should explicitly deny receipt persistence failure, output=%s", stdout.String())
	}
}

func TestHookPreToolReturnsBlockingExitWhenDenyCannotBeWritten(t *testing.T) {
	tmp := t.TempDir()
	payload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /srv/production"}}`
	var stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, strings.NewReader(payload), failingHookWriter{}, &stderr)
	if code != 2 {
		t.Fatalf("hook exit = %d, want blocking exit 2; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "emit denial") {
		t.Fatalf("stderr missing denial write failure: %s", stderr.String())
	}
}

func TestHookPreToolDoesNotCreateCWDKeyWithoutHome(t *testing.T) {
	t.Setenv("HOME", "")
	workdir := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workdir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(previous)
	})
	payload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /srv/production"}}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "claude-code"}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "local receipt signer is unavailable") {
		t.Fatalf("HOME-less hook = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workdir, "keys", workstationSigningSeedName)); !os.IsNotExist(err) {
		t.Fatalf("HOME-less hook created a CWD signing key: %v", err)
	}
}

type failingHookWriter struct{}

func (failingHookWriter) Write([]byte) (int, error) {
	return 0, errors.New("test hook output failure")
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

func TestHookPreToolDenyIncludesModelActionableFeedback(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	payload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/helm-demo"},"session_id":"s-feedback","cwd":"/repo"}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
	}
	var out hookDecisionOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("hook output JSON: %v\n%s", err, stdout.String())
	}
	reason := out.HookSpecificOutput.PermissionDecisionReason
	for _, want := range []string{
		"[INBOX_KERNEL_POLICY_DENY]",
		"kernel=OPERATE_PERMISSIONS_EMPTY",
		"Remediation:",
		"Escalation:",
		"Do not retry",
	} {
		if !strings.Contains(reason, want) {
			t.Fatalf("deny reason missing %q:\n%s", want, reason)
		}
	}
}

func TestHookPreToolFailClosedDenyIncludesSteeringCode(t *testing.T) {
	tmp := t.TempDir()
	keyDir := filepath.Join(tmp, workstationSigningKeyDirectory)
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workstationSigningSeedPath(tmp), []byte(strings.Repeat("0", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /srv/production"},"session_id":"s-signer"}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "signer is unavailable") {
		t.Fatalf("operator-facing prefix lost: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "[INBOX_SIGNER_UNAVAILABLE]") || !strings.Contains(stdout.String(), "Remediation:") {
		t.Fatalf("fail-closed deny missing steering feedback: %s", stdout.String())
	}
}

func TestHookPreToolDoomLoopBreakerTripsOnIdenticalAttempts(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	payload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/helm-demo"},"session_id":"s-loop","cwd":"/repo"}`

	// First two identical attempts: ordinary policy deny with kernel code.
	for i := 1; i <= 2; i++ {
		var stdout, stderr bytes.Buffer
		code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("attempt %d exit = %d stderr = %s", i, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "OPERATE_PERMISSIONS_EMPTY") {
			t.Fatalf("attempt %d should be a policy deny, got %s", i, stdout.String())
		}
		if strings.Contains(stdout.String(), "INBOX_DOOM_LOOP_DETECTED") {
			t.Fatalf("attempt %d must not trip the breaker yet: %s", i, stdout.String())
		}
	}

	// Third identical attempt: circuit breaker forces escalation.
	preTripReceipts := len(globReceipts(t, tmp))
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("tripped exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) || !strings.Contains(stdout.String(), "INBOX_DOOM_LOOP_DETECTED") {
		t.Fatalf("third identical attempt must trip the breaker: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Stop retrying the identical call") {
		t.Fatalf("doom-loop deny missing steering remediation: %s", stdout.String())
	}

	// The breaker short-circuits before policy evaluation, so the tripped
	// attempt must not produce a new decision receipt.
	if receipts := globReceipts(t, tmp); len(receipts) != preTripReceipts {
		t.Fatalf("tripped attempt wrote receipts: before=%d after=%v", preTripReceipts, receipts)
	}

	// Breaker state is persisted per session under the data dir.
	statePath := filepath.Join(tmp, "state", "hook-doomloop.json")
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read doom-loop state: %v", err)
	}
	if !strings.Contains(string(raw), `"tripped":true`) || !strings.Contains(string(raw), "s-loop") {
		t.Fatalf("doom-loop state missing trip record: %s", raw)
	}

	// A different session is unaffected by the tripped session.
	other := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/helm-demo"},"session_id":"s-other","cwd":"/repo"}`
	stdout.Reset()
	stderr.Reset()
	code = runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, strings.NewReader(other), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("other session exit = %d stderr = %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "INBOX_DOOM_LOOP_DETECTED") {
		t.Fatalf("breaker leaked across sessions: %s", stdout.String())
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
