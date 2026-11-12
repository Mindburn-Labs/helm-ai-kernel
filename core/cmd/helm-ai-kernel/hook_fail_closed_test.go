// quantum_posture: these tests exercise hook receipts signed with the
// classical Ed25519 workstation seed; no post-quantum primitive is involved.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

// newReceipts returns the receipts written since before.
func (env hookBypassEnv) newReceipts(t *testing.T, before map[string]bool) []*contracts.WorkstationPolicyDecisionReceipt {
	t.Helper()
	var receipts []*contracts.WorkstationPolicyDecisionReceipt
	for _, path := range globReceipts(t, env.dataDir) {
		if before[path] {
			continue
		}
		receipt, err := workstation.LoadDecisionReceipt(path)
		if err != nil {
			t.Fatalf("load receipt %s: %v", path, err)
		}
		if ok, err := workstation.VerifyDecisionReceiptSignature(receipt); err != nil || !ok {
			t.Fatalf("receipt %s signature ok=%v err=%v", path, ok, err)
		}
		receipts = append(receipts, receipt)
	}
	return receipts
}

func (env hookBypassEnv) receiptSet(t *testing.T) map[string]bool {
	t.Helper()
	set := map[string]bool{}
	for _, path := range globReceipts(t, env.dataDir) {
		set[path] = true
	}
	return set
}

// A search glob too large to expand is refused at once, under a budget, with
// a reason that says so. It must not hold the hook past the client's timeout.
func TestHookRefusesASearchGlobTooLargeToExpand(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	raw, err := json.Marshal(map[string]any{
		"tool_name":  "Grep",
		"session_id": "large-glob",
		"cwd":        "/repo",
		"tool_input": map[string]any{"path": env.home, "glob": strings.Repeat("{a,b}", (1<<20)/5), "pattern": "."},
	})
	if err != nil {
		t.Fatal(err)
	}
	before := env.receiptSet(t)
	type outcome struct {
		code           int
		stdout, stderr string
		elapsed        time.Duration
	}
	done := make(chan outcome, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		start := time.Now()
		code := runHookPreToolCmd(env.args, bytes.NewReader(raw), &stdout, &stderr)
		done <- outcome{code, stdout.String(), stderr.String(), time.Since(start)}
	}()
	var got outcome
	select {
	case got = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the hook did not decide a 1 MiB brace glob within two seconds")
	}
	if got.code != 0 || !strings.Contains(got.stdout, `"permissionDecision":"deny"`) || !strings.Contains(got.stdout, "too large to expand") {
		t.Fatalf("exit %d stdout=%s stderr=%s, want a denial that says the glob is too large to expand", got.code, got.stdout, got.stderr)
	}
	if got.elapsed > time.Second {
		t.Fatalf("the hook took %s to decide a 1 MiB brace glob, want well under a second", got.elapsed)
	}
	if receipts := env.newReceipts(t, before); len(receipts) != 1 || !hasDenial(receipts, "TRUST_MATERIAL_ACCESS_DENIED") {
		t.Fatalf("receipts = [%s], want one DENY/TRUST_MATERIAL_ACCESS_DENIED", describeReceipts(receipts))
	}
}

// failReceiptWrite makes the nth receipt write of the test fail.
func failReceiptWrite(t *testing.T, nth int) {
	t.Helper()
	original := hookWriteReceipt
	writes := 0
	hookWriteReceipt = func(path, receiptDir string, receipt *contracts.WorkstationPolicyDecisionReceipt) (string, error) {
		writes++
		if writes == nth {
			return "", errors.New("injected receipt write failure")
		}
		return original(path, receiptDir, receipt)
	}
	t.Cleanup(func() { hookWriteReceipt = original })
}

// When a later receipt of a call cannot be written, the call is refused. An
// ALLOW receipt already written would stand for a call that never ran, so it
// is removed; a denial already written records a refusal that did happen, so
// it stays.
func TestHookRemovesOnlyAllowReceiptsWhenALaterWriteFails(t *testing.T) {
	for _, tc := range []struct {
		name        string
		command     string
		wantVerdict string // the verdict of what may remain; "" = nothing remains
	}{
		{"allowed call", "curl https://api.github.com/zen && cat /home/agent/.ssh/id_rsa", ""},
		{"denied call", "curl https://one.example/x https://two.example/y", contracts.WorkstationVerdictDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
			failReceiptWrite(t, 2)
			before := env.receiptSet(t)
			raw, err := json.Marshal(map[string]any{"tool_name": "Bash", "session_id": "write-failure", "cwd": "/repo", "tool_input": map[string]any{"command": tc.command}})
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if code := runHookPreToolCmd(env.args, bytes.NewReader(raw), &stdout, &stderr); code != 0 {
				t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) || !strings.Contains(stdout.String(), "receipt persistence is unavailable") {
				t.Fatalf("stdout = %s, want a denial for the receipt that could not be written", stdout.String())
			}
			receipts := env.newReceipts(t, before)
			if tc.wantVerdict == "" {
				if len(receipts) != 0 {
					t.Fatalf("an ALLOW receipt was left for a call that never ran: [%s]", describeReceipts(receipts))
				}
				return
			}
			if len(receipts) != 1 || receipts[0].Verdict != tc.wantVerdict {
				t.Fatalf("receipts = [%s], want the denial already written to stay", describeReceipts(receipts))
			}
		})
	}
}

// The hook decides on the first JSON value it reads. A client that leaves
// standard input open after the payload still gets its answer.
func TestHookAnswersWithoutWaitingForTheEndOfInput(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	reader, writer := io.Pipe()
	defer writer.Close()
	type outcome struct {
		code           int
		stdout, stderr string
	}
	done := make(chan outcome, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		code := runHookPreToolCmd(env.args, reader, &stdout, &stderr)
		done <- outcome{code, stdout.String(), stderr.String()}
	}()
	go func() {
		_, _ = writer.Write([]byte(`{"tool_name":"Bash","session_id":"open-stdin","cwd":"/repo","tool_input":{"command":"curl https://other.example/x"}}` + "\n"))
	}()
	select {
	case got := <-done:
		if got.code != 0 || !strings.Contains(got.stdout, `"permissionDecision":"deny"`) {
			t.Fatalf("exit %d stdout=%s stderr=%s, want a denial", got.code, got.stdout, got.stderr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the hook waited for the end of standard input instead of deciding on the payload it had read")
	}
}

// A payload over the input limit is not classified, but its receipt still
// binds what the hook read: the digest of those bytes, how many there were,
// and the tool when its name came before the limit.
func TestHookOversizedReceiptBindsTheBytesItRead(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	oversized := func(head, tail string) []byte {
		return []byte(head + strings.Repeat("a", hookMaxInputBytes) + tail)
	}
	for _, tc := range []struct {
		name     string
		raw      []byte
		wantTool string
	}{
		{"tool named first", oversized(`{"tool_name":"Bash","session_id":"big","cwd":"/repo","tool_input":{"command":"echo `, `"}}`), "Bash"},
		{"tool named in camel case", oversized(`{"toolName":"terminal","toolInput":{"command":"echo `, `"}}`), "terminal"},
		{"tool named after the limit", oversized(`{"session_id":"big","tool_input":{"command":"echo `, `"},"tool_name":"Bash"}`), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := env.receiptSet(t)
			var stdout, stderr bytes.Buffer
			if code := runHookPreToolCmd(env.args, bytes.NewReader(tc.raw), &stdout, &stderr); code != 0 {
				t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
			}
			receipts := env.newReceipts(t, before)
			if len(receipts) != 1 || receipts[0].ReasonCode != "TOOL_INPUT_TOO_LARGE" {
				t.Fatalf("receipts = [%s], want one DENY/TOOL_INPUT_TOO_LARGE", describeReceipts(receipts))
			}
			metadata := receipts[0].Request.Metadata
			read := tc.raw[:hookMaxInputBytes+1]
			if metadata["tool_input_binding"] != "payload-prefix-sha256" || metadata["tool_input_sha256"] != canonicalize.ComputeArtifactHash(read) || metadata["tool_input_bytes_read"] != strconv.Itoa(len(read)) {
				t.Fatalf("receipt does not bind the bytes the hook read: %+v", metadata)
			}
			if tc.wantTool == "" {
				if receipts[0].Request.ToolID != "unknown" || metadata["tool"] != "" {
					t.Fatalf("a tool named past the limit was reported: tool_id=%q tool=%q", receipts[0].Request.ToolID, metadata["tool"])
				}
				return
			}
			if receipts[0].Request.ToolID != tc.wantTool || metadata["tool"] != tc.wantTool {
				t.Fatalf("receipt names tool_id=%q tool=%q, want %q", receipts[0].Request.ToolID, metadata["tool"], tc.wantTool)
			}
		})
	}
}

// One call may name at most hookMaxSecretTargets credential paths; past that
// it is one secret-read decision that says how many paths it stands for.
func TestHookCapsTheSecretPathsOfOneCall(t *testing.T) {
	command := func(count int) map[string]any {
		var b strings.Builder
		b.WriteString("cat")
		for i := 0; i < count; i++ {
			fmt.Fprintf(&b, " /home/agent/.ssh/id_rsa_%d", i)
		}
		return map[string]any{"command": b.String()}
	}
	secrets := func(classifications []hookClassification) []hookClassification {
		var out []hookClassification
		for _, classification := range classifications {
			if classification.Class == "secret" {
				out = append(out, classification)
			}
		}
		return out
	}
	if atLimit := secrets(classifyPreToolPayloads(preToolPayload{ToolName: "Bash", ToolInput: command(hookMaxSecretTargets)}, nil)); len(atLimit) != hookMaxSecretTargets {
		t.Fatalf("%d credential paths gave %d secret decisions, want one each", hookMaxSecretTargets, len(atLimit))
	}
	overLimit := secrets(classifyPreToolPayloads(preToolPayload{ToolName: "Bash", ToolInput: command(hookMaxSecretTargets + 1)}, nil))
	if len(overLimit) != 1 || overLimit[0].Metadata["secret.target_count"] != strconv.Itoa(hookMaxSecretTargets+1) {
		t.Fatalf("%d credential paths gave %d secret decisions (%+v), want one that counts them all", hookMaxSecretTargets+1, len(overLimit), overLimit)
	}
}
