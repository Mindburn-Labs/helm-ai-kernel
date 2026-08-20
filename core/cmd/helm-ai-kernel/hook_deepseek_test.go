package main

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func TestHookDeepseekDenyEmitsClaudeJSONAndExit0(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	payload := `{"tool_name":"bash","tool_input":{"command":"rm -rf /tmp/helm-demo"},"session_id":"dsh-deny","cwd":"/repo"}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "deepseek", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("deepseek deny exit = %d, want 0 stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	var out hookDecisionOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("deepseek JSON: %v\n%s", err, stdout.String())
	}
	if out.HookSpecificOutput.HookEventName != "PreToolUse" || out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("deepseek DENY shape = %#v", out)
	}
	if !dshPreToolUseBlocks(stdout.String(), code) {
		t.Fatalf("DSH/bridge contract did not treat the DENY as a block:\n%s", stdout.String())
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

func TestDSHBridgeBlocksChosenDenyAndNotHermesOrWrongClaudeShape(t *testing.T) {
	var claude bytes.Buffer
	if err := writeHookDeny(&claude, "HELM denied shell operation: OPERATE_PERMISSIONS_EMPTY (receipt: /tmp/x)"); err != nil {
		t.Fatal(err)
	}
	if !dshPreToolUseBlocks(claude.String(), 0) {
		t.Fatalf("Claude hookSpecificOutput + exit 0 must block on DSH:\n%s", claude.String())
	}

	var hermes bytes.Buffer
	if err := writeHermesHookBlock(&hermes, "HELM denied shell operation"); err != nil {
		t.Fatal(err)
	}
	if dshPreToolUseBlocks(hermes.String(), 0) {
		t.Fatalf("Hermes {\"action\":\"block\"} + exit 0 must not be a DSH block:\n%s", hermes.String())
	}
	if !dshPreToolUseBlocks("", 2) {
		t.Fatal("DSH exit 2 must still fold to deny")
	}

	wrongEvent := `{"hookSpecificOutput":{"hookEventName":"PostToolUse","permissionDecision":"deny","permissionDecisionReason":"nope"}}`
	if dshPreToolUseBlocks(wrongEvent, 0) {
		t.Fatalf("mismatched hookEventName must discard permissionDecision:\n%s", wrongEvent)
	}
	missingEvent := `{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"nope"}}`
	if dshPreToolUseBlocks(missingEvent, 0) {
		t.Fatalf("missing hookEventName must discard permissionDecision:\n%s", missingEvent)
	}
	topLevelDeny := `{"decision":"deny","reason":"nope"}`
	if dshPreToolUseBlocks(topLevelDeny, 0) {
		t.Fatalf("top-level decision=deny is invalid on DSH and must not block:\n%s", topLevelDeny)
	}
}

func TestUppercaseClaudeMatcherDoesNotCatchDSHToolNames(t *testing.T) {
	claudeOnly := regexp.MustCompile(`^(Bash|Edit|Write|MultiEdit|mcp__.*)$`)
	dsh := regexp.MustCompile(setupHookMatcher("deepseek"))
	for _, name := range []string{
		"bash", "pwsh", "write", "edit", "str_replace_editor",
		"terminal_open", "terminal_send", "terminal_signal",
	} {
		if claudeOnly.MatchString(name) {
			t.Fatalf("uppercase-only Claude matcher silently matched DSH tool %q", name)
		}
		if !dsh.MatchString(name) {
			t.Fatalf("deepseek matcher did not classify DSH tool %q", name)
		}
	}
	if !claudeOnly.MatchString("Bash") || dsh.MatchString("Bash") {
		t.Fatal("Claude Bash must remain a Claude-only matcher hit")
	}
}

func TestHookDeepseekClassifiesNativeToolNames(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	cases := []struct {
		name    string
		payload string
	}{
		{name: "bash", payload: `{"tool_name":"bash","tool_input":{"command":"rm -rf /tmp/helm-demo"},"session_id":"d-bash","cwd":"/repo"}`},
		{name: "pwsh", payload: `{"tool_name":"pwsh","tool_input":{"command":"rm -rf /tmp/helm-demo"},"session_id":"d-pwsh","cwd":"/repo"}`},
		{name: "write", payload: `{"tool_name":"write","tool_input":{"file_path":".env","content":"SECRET=1"},"session_id":"d-write","cwd":"/repo"}`},
		{name: "edit", payload: `{"tool_name":"edit","tool_input":{"file_path":".dsh/cordis.patch.yml","old_string":"a","new_string":"b"},"session_id":"d-edit","cwd":"/repo"}`},
		{name: "str_replace_editor", payload: `{"tool_name":"str_replace_editor","tool_input":{"command":"str_replace","path":".dsh/helm-ai-kernel-hooks.json","old_str":"a","new_str":"b"},"session_id":"d-sre","cwd":"/repo"}`},
		{name: "terminal_send", payload: `{"tool_name":"terminal_send","tool_input":{"sessionId":"s1","text":"rm -rf /tmp/helm-demo"},"session_id":"d-term","cwd":"/repo"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runHookPreToolCmd([]string{"--client", "deepseek", "--data-dir", tmp}, strings.NewReader(tc.payload), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, want 0 stderr=%s stdout=%s", code, stderr.String(), stdout.String())
			}
			if !dshPreToolUseBlocks(stdout.String(), code) {
				t.Fatalf("classified DSH tool %s did not produce a DSH block:\n%s", tc.name, stdout.String())
			}
			var out hookDecisionOutput
			if err := json.Unmarshal(stdout.Bytes(), &out); err != nil || out.HookSpecificOutput.PermissionDecision != "deny" {
				t.Fatalf("block JSON = %s err=%v", stdout.String(), err)
			}
		})
	}
}

func TestHookDeepseekUnclassifiedIsPassthroughWithoutReceipt(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	cases := []struct {
		name    string
		payload string
	}{
		{name: "read", payload: `{"tool_name":"read","tool_input":{"file_path":"README.md"},"session_id":"d-pass","cwd":"/repo"}`},
		{name: "str_replace_editor_view", payload: `{"tool_name":"str_replace_editor","tool_input":{"command":"view","path":"README.md"},"session_id":"d-view","cwd":"/repo"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runHookPreToolCmd([]string{"--client", "deepseek", "--data-dir", tmp}, strings.NewReader(tc.payload), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("unclassified exit = %d, want 0 stderr=%s stdout=%s", code, stderr.String(), stdout.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("unclassified must not emit a DSH block:\n%s", stdout.String())
			}
			if receipts := globReceipts(t, tmp); len(receipts) != 0 {
				t.Fatalf("unclassified must not write a receipt: %v", receipts)
			}
		})
	}
}

func TestHookHermesShapedStdoutExit0IsNotADeepseekBlock(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	payload := `{"tool_name":"bash","tool_input":{"command":"rm -rf /tmp/helm-demo"},"session_id":"d-shape","cwd":"/repo"}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "hermes", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != hermesBlockExitCode {
		t.Fatalf("hermes deny exit = %d, want %d", code, hermesBlockExitCode)
	}
	if dshPreToolUseBlocks(stdout.String(), 0) {
		t.Fatalf("Hermes native DENY + exit 0 must remain fail-open for DSH:\n%s", stdout.String())
	}
	if !dshPreToolUseBlocks(stdout.String(), code) {
		t.Fatal("the same Hermes stdout with exit 2 must still fold to a DSH deny")
	}
}
