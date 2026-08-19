package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func TestHookHermesDenyEmitsNativeBlockAndExit2(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	payload := `{"tool_name":"terminal","tool_input":{"command":"rm -rf /tmp/helm-demo"},"session_id":"hermes-deny","cwd":"/repo"}`
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "hermes", "--data-dir", tmp}, strings.NewReader(payload), &stdout, &stderr)
	if code != hermesBlockExitCode {
		t.Fatalf("hermes deny exit = %d, want %d stderr=%s stdout=%s", code, hermesBlockExitCode, stderr.String(), stdout.String())
	}
	var block hermesHookBlock
	if err := json.Unmarshal(stdout.Bytes(), &block); err != nil {
		t.Fatalf("hermes block JSON: %v\n%s", err, stdout.String())
	}
	if block.Action != "block" || strings.TrimSpace(block.Message) == "" {
		t.Fatalf("hermes block = %#v", block)
	}
	if !hermesPreToolCallBlocks(stdout.String(), code) {
		t.Fatalf("native Hermes interpreter did not treat the DENY as a block:\n%s", stdout.String())
	}

	var claude hookDecisionOutput
	if err := json.Unmarshal(stdout.Bytes(), &claude); err != nil {
		t.Fatalf("stdout should still be JSON: %v", err)
	}
	if claude.HookSpecificOutput.PermissionDecision != "" {
		t.Fatalf("hermes DENY must not emit Claude hookSpecificOutput: %#v", claude)
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

func TestClaudeShapedStdoutExit0IsNotAHermesBlock(t *testing.T) {
	var claude bytes.Buffer
	if err := writeHookDeny(&claude, "HELM denied shell operation: OPERATE_PERMISSIONS_EMPTY (receipt: /tmp/x)"); err != nil {
		t.Fatal(err)
	}
	if hermesPreToolCallBlocks(claude.String(), 0) {
		t.Fatalf("Claude hookSpecificOutput + exit 0 must not be a Hermes block:\n%s", claude.String())
	}

	var hermes bytes.Buffer
	if err := writeHermesHookBlock(&hermes, "HELM denied shell operation"); err != nil {
		t.Fatal(err)
	}
	if !hermesPreToolCallBlocks(hermes.String(), hermesBlockExitCode) {
		t.Fatalf("Hermes native block + exit 2 must block:\n%s", hermes.String())
	}
	if !hermesPreToolCallBlocks("", hermesBlockExitCode) {
		t.Fatal("Hermes exit 2 must block even with empty stdout")
	}
}

func TestHookHermesClassifiesNativeToolNames(t *testing.T) {
	tmp := t.TempDir()
	restoreHookClock(t)
	cases := []struct {
		name    string
		payload string
	}{
		{name: "terminal", payload: `{"tool_name":"terminal","args":{"command":"rm -rf /tmp/helm-demo"},"session_id":"h-term","cwd":"/repo"}`},
		{name: "write_file", payload: `{"tool_name":"write_file","args":{"path":".env","content":"SECRET=1"},"session_id":"h-write","cwd":"/repo"}`},
		{name: "patch", payload: `{"tool_name":"patch","args":{"path":".hermes/config.yaml","diff":"*** Update File: .hermes/config.yaml\n"},"session_id":"h-patch","cwd":"/repo"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runHookPreToolCmd([]string{"--client", "hermes", "--data-dir", tmp}, strings.NewReader(tc.payload), &stdout, &stderr)
			if code != hermesBlockExitCode {
				t.Fatalf("exit = %d, want %d stderr=%s stdout=%s", code, hermesBlockExitCode, stderr.String(), stdout.String())
			}
			if !hermesPreToolCallBlocks(stdout.String(), code) {
				t.Fatalf("classified Hermes tool %s did not produce a native block:\n%s", tc.name, stdout.String())
			}
			var block hermesHookBlock
			if err := json.Unmarshal(stdout.Bytes(), &block); err != nil || block.Action != "block" {
				t.Fatalf("block JSON = %s err=%v", stdout.String(), err)
			}
		})
	}
}

func TestHookClaudeDenyStillUsesClaudeJSONAndExit0(t *testing.T) {
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
	if hermesPreToolCallBlocks(stdout.String(), code) {
		t.Fatalf("existing Claude DENY shape must remain fail-open for Hermes:\n%s", stdout.String())
	}
}
