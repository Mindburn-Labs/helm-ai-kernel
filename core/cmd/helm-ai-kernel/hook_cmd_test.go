package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/actioninbox"
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

	// First two identical settled denials: ordinary policy deny, no trip.
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

	// Third identical settled denial: policy deny stands, breaker upgrades
	// the steering text. The denial is still evaluated and receipted — the
	// breaker never short-circuits the authoritative policy path.
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("tripped exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) || !strings.Contains(stdout.String(), "INBOX_DOOM_LOOP_DETECTED") {
		t.Fatalf("third identical denial must trip the breaker: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "OPERATE_PERMISSIONS_EMPTY") {
		t.Fatalf("tripped denial must still carry the kernel reason code: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Stop retrying the identical call") {
		t.Fatalf("doom-loop deny missing steering remediation: %s", stdout.String())
	}
	if receipts := globReceipts(t, tmp); len(receipts) == 0 {
		t.Fatal("tripped denial must still produce a decision receipt")
	}

	// Breaker state is persisted per session under the data dir, latched
	// per call signature.
	statePath := filepath.Join(tmp, "state", "hook-doomloop.json")
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read doom-loop state: %v", err)
	}
	if !strings.Contains(string(raw), `"tripped_signatures"`) || !strings.Contains(string(raw), "s-loop") {
		t.Fatalf("doom-loop state missing per-signature trip record: %s", raw)
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

// TestHookPreToolDoomLoopLatchIsPerSignature is the regression test for the
// session-permalock blocker: after a trip, a CHANGED approach (different
// signature) in the same session must go through the normal policy path
// without doom-loop steering, while retrying the tripped identical call
// keeps the escalation steering.
func TestHookPreToolDoomLoopLatchIsPerSignature(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	sigA := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/helm-demo"},"session_id":"s-latch","cwd":"/repo"}`
	sigB := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /var/other-target"},"session_id":"s-latch","cwd":"/repo"}`

	run := func(payload string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
		}
		return stdout.String()
	}

	// Trip the breaker on sigA (3 identical settled denials).
	for i := 1; i <= 3; i++ {
		run(sigA)
	}

	// Post-trip, a different signature in the same session is a fresh
	// evaluation: policy deny without doom-loop steering.
	out := run(sigB)
	if !strings.Contains(out, `"permissionDecision":"deny"`) || !strings.Contains(out, "OPERATE_PERMISSIONS_EMPTY") {
		t.Fatalf("changed approach must follow the normal policy path: %s", out)
	}
	if strings.Contains(out, "INBOX_DOOM_LOOP_DETECTED") {
		t.Fatalf("changed approach must not inherit the tripped session's latch: %s", out)
	}

	// Retrying the tripped identical call keeps the escalation steering
	// (latch is per signature and survives interleaved calls).
	out = run(sigA)
	if !strings.Contains(out, "INBOX_DOOM_LOOP_DETECTED") {
		t.Fatalf("retry of tripped signature must keep escalation steering: %s", out)
	}
}

// TestHookDoomLoopOutcomeLogic unit-tests the pure settled-outcome logic:
// only settled denials count, allowed calls reset the run and can never
// trip, and the latch is per signature.
func TestHookDoomLoopOutcomeLogic(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	sigA := actioninbox.SignatureFor("shell", "shell_operate", "rm -rf /a")
	sigB := actioninbox.SignatureFor("shell", "shell_operate", "rm -rf /b")

	sess := &hookDoomLoopSession{}
	// Allowed calls never trip and reset the run.
	sess.recordAllowed()
	if tripped, run := sess.recordDenied(sigA, now); tripped || run != 1 {
		t.Fatalf("first denial: tripped=%v run=%d, want false/1", tripped, run)
	}
	sess.recordAllowed()
	if tripped, run := sess.recordDenied(sigA, now); tripped || run != 1 {
		t.Fatalf("allowed call must reset the run: tripped=%v run=%d, want false/1", tripped, run)
	}
	// Consecutive denials trip at the threshold.
	sess.recordDenied(sigA, now)
	if tripped, _ := sess.recordDenied(sigA, now); !tripped {
		t.Fatal("third consecutive identical denial must trip")
	}
	// Latch is per signature: sigB fresh, sigA latched even interleaved.
	if tripped, run := sess.recordDenied(sigB, now); tripped || run != 1 {
		t.Fatalf("different signature must start fresh: tripped=%v run=%d", tripped, run)
	}
	if tripped, _ := sess.recordDenied(sigA, now); !tripped {
		t.Fatal("latched signature must stay tripped after interleave")
	}
}

// TestHookDoomLoopPrune covers TTL expiry and the session cap.
func TestHookDoomLoopPrune(t *testing.T) {
	now := time.Unix(100000, 0).UTC()
	state := &hookDoomLoopFile{Sessions: map[string]*hookDoomLoopSession{}}
	state.Sessions["fresh"] = &hookDoomLoopSession{LastSeenAt: now.Add(-time.Hour)}
	state.Sessions["stale"] = &hookDoomLoopSession{LastSeenAt: now.Add(-48 * time.Hour)}
	state.Sessions["legacy-zero"] = &hookDoomLoopSession{}
	pruneHookDoomLoopSessions(state, now)
	if _, ok := state.Sessions["stale"]; ok {
		t.Fatal("TTL-expired session must be pruned")
	}
	if _, ok := state.Sessions["legacy-zero"]; ok {
		t.Fatal("zero LastSeenAt (legacy state) must be pruned")
	}
	if _, ok := state.Sessions["fresh"]; !ok {
		t.Fatal("fresh session must survive pruning")
	}

	for i := 0; i < hookDoomLoopMaxSessions+10; i++ {
		id := fmt.Sprintf("s-%d", i)
		state.Sessions[id] = &hookDoomLoopSession{LastSeenAt: now.Add(time.Duration(i) * time.Second)}
	}
	pruneHookDoomLoopSessions(state, now)
	if len(state.Sessions) != hookDoomLoopMaxSessions {
		t.Fatalf("session cap: got %d, want %d", len(state.Sessions), hookDoomLoopMaxSessions)
	}
}

// TestHookDoomLoopConcurrentRecordsNoLostUpdates is the regression test for
// the state race: parallel hook invocations must serialize through the lock
// so no settled-denial record is lost.
func TestHookDoomLoopConcurrentRecordsNoLostUpdates(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	opts := hookOptions{DataDir: tmp}
	payload := preToolPayload{ToolName: "Bash", SessionID: "s-race"}
	classification := hookClassification{ToolID: "shell", Action: "shell_operate", Target: "rm -rf /race"}

	const workers = 12
	var wg sync.WaitGroup
	var stderr bytes.Buffer
	var mu sync.Mutex
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var buf bytes.Buffer
			recordHookDoomLoopOutcome(opts, payload, classification, true, &buf)
			mu.Lock()
			stderr.Write(buf.Bytes())
			mu.Unlock()
		}()
	}
	wg.Wait()

	raw, err := os.ReadFile(filepath.Join(tmp, "state", "hook-doomloop.json"))
	if err != nil {
		t.Fatalf("read state: %v (stderr: %s)", err, stderr.String())
	}
	var state hookDoomLoopFile
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("parse state: %v", err)
	}
	sess := state.Sessions["s-race"]
	if sess == nil {
		t.Fatalf("session missing after concurrent records: %s", raw)
	}
	if sess.RunLength != workers {
		t.Fatalf("lost updates under concurrency: run=%d, want %d", sess.RunLength, workers)
	}
	sig := actioninbox.SignatureFor("shell", "shell_operate", "rm -rf /race")
	if !sess.TrippedSignatures[sig] {
		t.Fatalf("breaker must be latched after %d identical denials", workers)
	}
	if left := filepath.Join(tmp, "state", "hook-doomloop.json.lock"); fileExists(left) {
		t.Fatalf("lock file left behind: %s", left)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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
