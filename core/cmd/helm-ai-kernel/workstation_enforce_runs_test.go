// quantum_posture: these tests exercise workstation receipts signed with the
// classical Ed25519 workstation seed; no post-quantum primitive is involved.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// A command enforce refuses because no receipt covers running it (an
// observe-mode ALLOW does not) leaves no ALLOW receipt: the refusal is settled
// before any receipt is written, as a denial is.
func TestWorkstationEnforceLeavesNoAllowForACommandItRefuses(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "helm")
	marker := filepath.Join(t.TempDir(), "observe-mode-executed")
	var stdout, stderr bytes.Buffer
	code := Run(enforceArgs(dataDir, "", "--class", "shell", "--", "/usr/bin/touch", marker), &stdout, &stderr)
	if code != 126 {
		t.Fatalf("exit = %d, want 126 (stderr=%s)", code, stderr.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("the refused command ran: %v", err)
	}
	if receipts := enforceReceipts(t, dataDir); len(receipts) != 0 {
		t.Fatalf("a refused command left %d receipts (%s first), want none", len(receipts), receipts[0].Verdict)
	}
}

// Two runs of the same command keep both runs' receipts: every receipt has a
// request of its own, and a receipt file is never replaced.
func TestWorkstationEnforceKeepsTheReceiptsOfEveryRun(t *testing.T) {
	allow := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	clearEnforceEnvironment(t)
	dataDir := filepath.Join(t.TempDir(), "helm")
	var stdout, stderr bytes.Buffer
	run := func() {
		t.Helper()
		stdout.Reset()
		stderr.Reset()
		if code := Run(enforceArgs(dataDir, allow, "--class", "shell-operate", "--", "/usr/bin/true"), &stdout, &stderr); code != 0 {
			t.Fatalf("exit = %d stderr = %s", code, stderr.String())
		}
	}
	run()
	first := len(enforceReceipts(t, dataDir))
	if first == 0 {
		t.Fatal("the first run left no receipt")
	}
	run()
	receipts := enforceReceipts(t, dataDir)
	if len(receipts) != 2*first {
		t.Fatalf("two runs left %d receipts, want %d", len(receipts), 2*first)
	}
	requests, calls := map[string]bool{}, map[string]bool{}
	for _, receipt := range receipts {
		requests[receipt.Request.RequestID] = true
		calls[receipt.Request.Metadata["call_id"]] = true
	}
	if len(requests) != len(receipts) || len(calls) != 2 {
		t.Fatalf("%d receipts carry %d request IDs and %d call IDs, want one request each and one call per run", len(receipts), len(requests), len(calls))
	}
}

// When a later receipt of a run cannot be written the command does not run.
// An ALLOW already written would stand for a command that never ran, so it is
// removed; a denial already written records a refusal that did happen, so it
// stays.
func TestWorkstationEnforceRemovesOnlyAllowReceiptsWhenALaterWriteFails(t *testing.T) {
	allow := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	for _, tc := range []struct {
		name      string
		args      []string
		wantKept  bool
		wantFirst string
	}{
		{"allowed run", []string{"--class", "shell-operate", "--", "curl", "https://api.github.com/zen"}, false, contracts.WorkstationVerdictAllow},
		{"denied run", []string{"--class", "network", "--", "curl", "https://one.example/x", "https://two.example/y"}, true, contracts.WorkstationVerdictDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker := enforceShim(t, "curl")
			dataDir := filepath.Join(t.TempDir(), "helm")
			out := filepath.Join(t.TempDir(), "decisive.json")
			blocked := filepath.Join(t.TempDir(), "not-a-directory")
			if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			// The first receipt goes to --out, which works; the second to
			// --receipt-dir, which cannot be created.
			args := append([]string{"helm-ai-kernel", "workstation", "enforce", "--data-dir", dataDir, "--out", out, "--receipt-dir", filepath.Join(blocked, "receipts"), "--policy-profile", allow}, tc.args...)
			var stdout, stderr bytes.Buffer
			if code := Run(args, &stdout, &stderr); code != 126 {
				t.Fatalf("exit = %d, want 126 (stderr=%s)", code, stderr.String())
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("the command ran although a receipt could not be written")
			}
			_, err := os.Stat(out)
			if kept := err == nil; kept != tc.wantKept {
				t.Fatalf("first receipt kept = %v, want %v", kept, tc.wantKept)
			}
			if tc.wantKept {
				if receipt := readDecisionReceipt(t, out); receipt.Verdict != tc.wantFirst {
					t.Fatalf("kept receipt verdict = %s, want %s", receipt.Verdict, tc.wantFirst)
				}
			}
		})
	}
}
