package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func TestHookDeepSeekDenyEmitsNativeDenyAndExit2(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	payload := `{"tool_name":"bash","tool_input":{"command":"rm -rf /tmp/helm-demo"},"session_id":"deepseek-deny","cwd":"/repo"}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "deepseek", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != deepseekBlockExitCode {
		t.Fatalf("deepseek deny exit = %d, want %d stderr=%s stdout=%s", code, deepseekBlockExitCode, stderr.String(), stdout.String())
	}
	var deny deepseekHookDeny
	if err := json.Unmarshal(stdout.Bytes(), &deny); err != nil {
		t.Fatalf("deepseek deny JSON: %v\n%s", err, stdout.String())
	}
	if deny.Kind != "deny" || strings.TrimSpace(deny.Reason) == "" {
		t.Fatalf("deepseek deny = %#v", deny)
	}
	if !strings.Contains(stderr.String(), deny.Reason) {
		t.Fatalf("DSH parseHookOutput reads the reason from stderr; stderr=%q want %q", stderr.String(), deny.Reason)
	}
	block, reason := deepseekParseHookOutput(stdout.String(), stderr.String(), code)
	if !block || reason != strings.TrimSpace(deny.Reason) {
		t.Fatalf("DSH parseHookOutput block=%v reason=%q, want block with %q", block, reason, deny.Reason)
	}
	if !deepseekPreToolBlocks(stdout.String(), code) {
		t.Fatalf("exit 2 must be a DSH block; stdout=%s", stdout.String())
	}

	var claude hookDecisionOutput
	if err := json.Unmarshal(stdout.Bytes(), &claude); err != nil {
		t.Fatalf("stdout should still be JSON: %v", err)
	}
	if claude.HookSpecificOutput.PermissionDecision != "" {
		t.Fatalf("deepseek DENY must not emit Claude hookSpecificOutput: %#v", claude)
	}

	receipts := globReceipts(t, tmp)
	if len(receipts) != 1 {
		t.Fatalf("receipts = %v, want one under receipts/hooks", receipts)
	}
	receipt, err := workstation.LoadDecisionReceipt(receipts[0])
	if err != nil {
		t.Fatalf("load receipt: %v", err)
	}
	if receipt.Verdict != contracts.WorkstationVerdictDeny {
		t.Fatalf("receipt verdict = %s, want DENY", receipt.Verdict)
	}
}

func TestClaudeShapedStdoutExit0IsNotADeepSeekBlock(t *testing.T) {
	var claude bytes.Buffer
	if err := writeHookDeny(&claude, "HELM denied shell operation: OPERATE_PERMISSIONS_EMPTY (receipt: /tmp/x)"); err != nil {
		t.Fatal(err)
	}
	if deepseekPreToolBlocks(claude.String(), 0) {
		t.Fatalf("Claude hookSpecificOutput + exit 0 must not be a DeepSeek block:\n%s", claude.String())
	}

	var deepseek, reasonBuf bytes.Buffer
	if err := writeDeepSeekHookDeny(&deepseek, &reasonBuf, "HELM denied shell operation"); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(reasonBuf.String()) != "HELM denied shell operation" {
		t.Fatalf("writeDeepSeekHookDeny stderr = %q, want the HELM reason", reasonBuf.String())
	}
	if !deepseekPreToolBlocks(deepseek.String(), deepseekBlockExitCode) {
		t.Fatalf("DeepSeek exit 2 must block even with native stdout:\n%s", deepseek.String())
	}
	if !deepseekPreToolBlocks("", deepseekBlockExitCode) {
		t.Fatal("DeepSeek exit 2 must block even with empty stdout")
	}
	if deepseekPreToolBlocks(`{"kind":"deny","reason":"ignored"}`, 0) {
		t.Fatal(`{"kind":"deny"} is never read; exit 0 must not be a DSH block`)
	}
	block, reason := deepseekParseHookOutput(`{"kind":"deny","reason":"ignored"}`, "HELM denied shell operation", deepseekBlockExitCode)
	if !block || reason != "HELM denied shell operation" {
		t.Fatalf("exit 2 must take the reason from stderr, got block=%v reason=%q", block, reason)
	}
}

func TestHookDeepSeekClassifiesNativeToolNames(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	cases := []struct {
		name    string
		payload string
	}{
		{name: "bash", payload: `{"tool_name":"bash","args":{"command":"rm -rf /tmp/helm-demo"},"session_id":"d-bash","cwd":"/repo"}`},
		{name: "write", payload: `{"tool_name":"write","args":{"path":".env","content":"SECRET=1"},"session_id":"d-write","cwd":"/repo"}`},
		{name: "edit", payload: `{"tool_name":"edit","args":{"path":".dsh/hooks.json","diff":"*** Update File: .dsh/hooks.json\n"},"session_id":"d-edit","cwd":"/repo"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runHookPreToolCmd([]string{"--client", "deepseek", "--data-dir", tmp}, strings.NewReader(tc.payload), &stdout, &stderr)
			if code != deepseekBlockExitCode {
				t.Fatalf("exit = %d, want %d stderr=%s stdout=%s", code, deepseekBlockExitCode, stderr.String(), stdout.String())
			}
			if !deepseekPreToolBlocks(stdout.String(), code) {
				t.Fatalf("classified DeepSeek tool %s did not exit 2:\n%s", tc.name, stdout.String())
			}
			var deny deepseekHookDeny
			if err := json.Unmarshal(stdout.Bytes(), &deny); err != nil || deny.Kind != "deny" {
				t.Fatalf("deny JSON = %s err=%v", stdout.String(), err)
			}
			if !strings.Contains(stderr.String(), deny.Reason) {
				t.Fatalf("classified DeepSeek tool %s stderr missing reason %q:\n%s", tc.name, deny.Reason, stderr.String())
			}
		})
	}
}

func TestClassifyDeepSeekMCPToolNames(t *testing.T) {
	for _, tool := range []string{"mcp_filesystem_write_file", "mcp__filesystem__write_file"} {
		got := classifyPreToolPayload(preToolPayload{ToolName: tool})
		if !got.ShouldDecide || got.Class != "mcp" || got.Target != tool {
			t.Fatalf("%s classified as %#v", tool, got)
		}
	}
}

func TestHookDeepSeekUnclassifiedIsPassthroughWithoutReceipt(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	payload := `{"tool_name":"read","args":{"path":"README.md"},"session_id":"d-pass","cwd":"/repo"}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "deepseek", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unclassified exit = %d, want 0 stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("unclassified must not emit a DeepSeek deny:\n%s", stdout.String())
	}
	if receipts := globReceipts(t, tmp); len(receipts) != 0 {
		t.Fatalf("unclassified must not write a receipt: %v", receipts)
	}
}

func TestHookClaudeDenyIsNotADeepSeekBlock(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	payload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/helm-demo"},"session_id":"claude-shape","cwd":"/repo"}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "claude-code", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("claude-code deny exit = %d, want 0", code)
	}
	var out hookDecisionOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("claude JSON: %v\n%s", err, stdout.String())
	}
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("claude decision = %q", out.HookSpecificOutput.PermissionDecision)
	}
	if deepseekPreToolBlocks(stdout.String(), code) {
		t.Fatalf("existing Claude DENY shape must remain fail-open for DeepSeek:\n%s", stdout.String())
	}
}

func TestWriteDeepSeekHookDenyPutsMatchingReasonOnStderr(t *testing.T) {
	reason := "HELM denied shell operation: OPERATE_PERMISSIONS_EMPTY (receipt: /tmp/x)"
	var stdout, stderr bytes.Buffer
	if err := writeDeepSeekHookDeny(&stdout, &stderr, reason); err != nil {
		t.Fatal(err)
	}
	var deny deepseekHookDeny
	if err := json.Unmarshal(stdout.Bytes(), &deny); err != nil {
		t.Fatalf("stdout JSON: %v\n%s", err, stdout.String())
	}
	if deny.Kind != "deny" || deny.Reason != reason {
		t.Fatalf("stdout deny = %#v, want kind=deny reason=%q", deny, reason)
	}
	got := strings.TrimSpace(stderr.String())
	if got == "" || got != reason {
		t.Fatalf("stderr reason = %q, want non-empty match of stdout reason %q", got, reason)
	}
	block, parsed := deepseekParseHookOutput(stdout.String(), stderr.String(), deepseekBlockExitCode)
	if !block || parsed != reason {
		t.Fatalf("parseHookOutput block=%v reason=%q, want block with %q", block, parsed, reason)
	}
}

func TestHookDeepSeekFailClosedDenyWritesReasonToStderr(t *testing.T) {
	tmp := t.TempDir()
	keyDir := filepath.Join(tmp, workstationSigningKeyDirectory)
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workstationSigningSeedPath(tmp), []byte(strings.Repeat("0", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := `{"tool_name":"bash","tool_input":{"command":"rm -rf /srv/production"},"session_id":"deepseek-fail-closed","cwd":"/repo"}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "deepseek", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != deepseekBlockExitCode {
		t.Fatalf("fail-closed exit = %d, want %d stderr=%s stdout=%s", code, deepseekBlockExitCode, stderr.String(), stdout.String())
	}
	var deny deepseekHookDeny
	if err := json.Unmarshal(stdout.Bytes(), &deny); err != nil {
		t.Fatalf("stdout JSON: %v\n%s", err, stdout.String())
	}
	if deny.Kind != "deny" || !strings.Contains(deny.Reason, "signer is unavailable") {
		t.Fatalf("fail-closed stdout deny = %#v", deny)
	}
	if strings.TrimSpace(deny.Reason) == "" || !strings.Contains(stderr.String(), deny.Reason) {
		t.Fatalf("fail-closed stderr must carry the same HELM reason as stdout\nstdout=%q\nstderr=%q", deny.Reason, stderr.String())
	}
}

func TestHookDeepSeekDenyWritesReasonToStderr(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	payload := `{"tool_name":"bash","tool_input":{"command":"rm -rf /tmp/helm-demo"},"session_id":"deepseek-stderr","cwd":"/repo"}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "deepseek", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != deepseekBlockExitCode {
		t.Fatalf("exit = %d, want %d stderr=%s stdout=%s", code, deepseekBlockExitCode, stderr.String(), stdout.String())
	}
	var deny deepseekHookDeny
	if err := json.Unmarshal(stdout.Bytes(), &deny); err != nil {
		t.Fatalf("stdout JSON: %v\n%s", err, stdout.String())
	}
	if deny.Kind != "deny" || strings.TrimSpace(deny.Reason) == "" {
		t.Fatalf("stdout deny = %#v", deny)
	}
	if strings.TrimSpace(stderr.String()) == "" {
		t.Fatal("stderr must carry the HELM deny reason for DSH parseHookOutput")
	}
	if !strings.Contains(stderr.String(), deny.Reason) {
		t.Fatalf("stderr must carry the same reason as stdout kind/reason\nstdout=%q\nstderr=%q", deny.Reason, stderr.String())
	}
	block, reason := deepseekParseHookOutput(stdout.String(), stderr.String(), code)
	if !block {
		t.Fatal("exit 2 must block")
	}
	if reason != strings.TrimSpace(deny.Reason) {
		t.Fatalf("parsed reason = %q, want %q", reason, deny.Reason)
	}
}
