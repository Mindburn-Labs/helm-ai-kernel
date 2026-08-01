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
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shellscan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func TestHookPreToolDeniesDestructiveBashAndWritesReceipt(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	command := "rm -rf /tmp/helm-demo"
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
	if receipt.Request.Target != fingerprintHookTarget(command) {
		t.Fatalf("receipt target = %q, want fingerprint", receipt.Request.Target)
	}
	if receipt.Request.Metadata["target_binding"] != "sha256:utf-8" {
		t.Fatalf("target binding = %q, want sha256:utf-8", receipt.Request.Metadata["target_binding"])
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
	if strings.Contains(string(raw), command) {
		t.Fatalf("receipt leaked raw command: %s", string(raw))
	}
	tampered := filepath.Join(tmp, "tampered-decision.json")
	if err := os.WriteFile(tampered, []byte(strings.Replace(string(raw), fingerprintHookTarget(command), fingerprintHookTarget(command+"2"), 1)), 0o600); err != nil {
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

func TestHookPreToolPersistsAllowReceiptWithCustomPolicyProfile(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	command := "rm -rf /tmp/helm-allow"
	payload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/helm-allow"},"session_id":"allow-session","cwd":"/repo"}`
	profile := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "codex", "--data-dir", tmp, "--policy-profile", profile}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("allow hook should not emit denial output, got %s", stdout.String())
	}
	receipts := globReceipts(t, tmp)
	if len(receipts) != 1 {
		t.Fatalf("receipts = %v, want one", receipts)
	}
	receipt, err := workstation.LoadDecisionReceipt(receipts[0])
	if err != nil {
		t.Fatalf("load receipt: %v", err)
	}
	if receipt.Verdict != contracts.WorkstationVerdictAllow {
		t.Fatalf("verdict = %s, want ALLOW", receipt.Verdict)
	}
	if receipt.Request.Target != fingerprintHookTarget(command) {
		t.Fatalf("receipt target = %q, want fingerprint", receipt.Request.Target)
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
}

func TestBuildHookDecisionReceiptEvaluatesRawTargetBeforePersistingFingerprint(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	target := "https://api.github.com/repos/Mindburn-Labs/helm"
	profile := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	receipt, err := buildHookDecisionReceipt(
		hookOptions{Client: "codex", DataDir: tmp, PolicyProfile: profile},
		preToolPayload{ToolName: "Bash", SessionID: "network-allow", CWD: "/repo"},
		hookClassification{
			ShouldDecide: true,
			Class:        "network",
			Target:       target,
			Action:       "network_egress",
			ToolID:       "shell",
			Reason:       "network egress",
		},
	)
	if err != nil {
		t.Fatalf("build receipt: %v", err)
	}
	if receipt.Verdict != contracts.WorkstationVerdictAllow {
		t.Fatalf("verdict = %s/%s, want ALLOW", receipt.Verdict, receipt.ReasonCode)
	}
	if receipt.Request.Target != fingerprintHookTarget(target) {
		t.Fatalf("receipt target = %q, want fingerprint", receipt.Request.Target)
	}
	path, err := writeDecisionReceipt(filepath.Join(tmp, "hook-network.json"), "", receipt)
	if err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	if strings.Contains(string(raw), target) {
		t.Fatalf("receipt leaked raw target: %s", string(raw))
	}
	if ok, err := workstation.VerifyDecisionReceiptSignature(receipt); err != nil || !ok {
		t.Fatalf("receipt signature ok=%v err=%v", ok, err)
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

func TestHookPreToolFailsClosedWhenAllowReceiptCannotPersist(t *testing.T) {
	tmp := t.TempDir()
	if _, err := ensureLocalWorkstationSigningSeed(tmp); err != nil {
		t.Fatalf("prepare local signing key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "receipts"), []byte("not a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	payload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /srv/allowed-by-profile"}}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp, "--policy-profile", profile}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) || !strings.Contains(stdout.String(), "receipt persistence is unavailable") {
		t.Fatalf("hook should explicitly deny allow-receipt persistence failure, output=%s", stdout.String())
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
	if receipt.Request.Target != fingerprintHookTarget(".env") {
		t.Fatalf("receipt target = %q, want fingerprint", receipt.Request.Target)
	}
}

func TestHookPreToolDeniesEvasiveBashViaASTClassifier(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	// This matrix covers both legacy-needle parity and AST-only evasions; all
	// must route through the signed decision path and deny by default.
	evasive := []string{
		"rm -r -f /tmp/helm-evasion",                                             // split flags
		"sudo rm -rf /var/lib/helm-evasion",                                      // privilege wrapper
		`bash -c "rm -rf /tmp/helm-evasion"`,                                     // shell -c wrapper
		"cat targets.txt | xargs rm -rf",                                         // pipe into xargs
		"echo ok && rm -rf /tmp/helm-evasion",                                    // chaining
		"find /tmp/helm-evasion -delete",                                         // find -delete
		"echo cm0gLXJmIC8= | base64 -d | sh",                                     // decode into shell
		"echo SECRET=x >> .env",                                                  // sensitive redirect
		"rm --recursive --force /tmp/helm-evasion",                               // long flags
		"/bin/./rm -rf /tmp/helm-evasion",                                        // path obfuscation
		"python <<'PY'\nimport shutil\nshutil.rmtree('/tmp/helm-evasion')\nPY",   // interpreter heredoc
		"python - <<'PY'\nimport shutil\nshutil.rmtree('/tmp/helm-evasion')\nPY", // stdin marker + heredoc
		"perl <<'PL'\nunlink '/tmp/helm-evasion'\nPL",                            // interpreter heredoc
		"ruby <<'RB'\nFile.delete('/tmp/helm-evasion')\nRB",                      // interpreter heredoc
		"node <<'JS'\nrequire('fs').rmSync('/tmp/helm-evasion')\nJS",             // interpreter heredoc
		"cat <<'PY' >/tmp/run.py\nimport shutil\nshutil.rmtree('/tmp/helm-evasion')\nPY\npython /tmp/run.py",    // generated script
		"printf 'import shutil\\nshutil.rmtree(\\\"/tmp/helm-evasion\\\")\\n' >/tmp/run.py; python /tmp/run.py", // generated script
		"python <(printf 'import shutil\\nshutil.rmtree(\\\"/tmp/helm-evasion\\\")\\n')",                        // process substitution
	}
	for _, command := range evasive {
		t.Run(command, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{
				"tool_name":  "Bash",
				"tool_input": map[string]any{"command": command},
				"session_id": "evasion",
			})
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, bytes.NewReader(payload), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
				t.Fatalf("evasive command %q not denied, output = %s", command, stdout.String())
			}
		})
	}
	if receipts := globReceipts(t, tmp); len(receipts) != len(evasive) {
		t.Fatalf("receipts = %d, want %d (one signed receipt per denied evasion)", len(receipts), len(evasive))
	}
}

func TestShellscanReceiptMetadataPreservesAuditSignals(t *testing.T) {
	scan := shellscan.Classify("sudo rm -r -f /tmp/x")
	metadata := shellscanReceiptMetadata(scan)
	if metadata["shellscan.parse_ok"] != "true" {
		t.Fatalf("parse metadata = %q", metadata["shellscan.parse_ok"])
	}
	if metadata["shellscan.signals"] == "" {
		t.Fatal("signals metadata missing")
	}
	if !strings.Contains(metadata["shellscan.commands"], "rm via sudo") {
		t.Fatalf("wrapper chain missing from %q", metadata["shellscan.commands"])
	}
}

func TestHookPreToolStillAllowsBenignBashAfterASTClassifier(t *testing.T) {
	tmp := t.TempDir()
	benign := []string{
		"git status --short",
		"go build ./... && go vet ./...",
		"git log --oneline | head -5",
		`echo "today is $(date +%F)"`,
		"npm run build",
		"python --version",
		`bash scripts/deploy.sh "$ARG"`,
		"kubectl get pods -n prod",
	}
	for _, command := range benign {
		t.Run(command, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{
				"tool_name":  "Bash",
				"tool_input": map[string]any{"command": command},
			})
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := runHookPreToolCmd([]string{"--client", "codex", "--data-dir", tmp}, bytes.NewReader(payload), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("benign command %q emitted approval output: %s", command, stdout.String())
			}
		})
	}
	if receipts := globReceipts(t, tmp); len(receipts) != 0 {
		t.Fatalf("benign commands wrote receipts: %v", receipts)
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
