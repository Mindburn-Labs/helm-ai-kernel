// quantum_posture: these tests exercise workstation receipts signed with the
// classical Ed25519 workstation seed; no post-quantum primitive is involved.

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

// A refused command leaves only its denials, as a refused hook call does: an
// ALLOW receipt for an effect of a command that never ran would be counted as
// an allowed action. Every receipt of one run carries the same call binding.
func TestWorkstationEnforceWritesOnlyTheDenialsOfARefusedCommand(t *testing.T) {
	allow := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	marker := enforceShim(t, "curl")
	dataDir := filepath.Join(t.TempDir(), "helm")
	var stdout, stderr bytes.Buffer
	code := Run(enforceArgs(dataDir, allow, "--class", "network", "--", "curl", "https://api.github.com/zen", "https://other.example/x"), &stdout, &stderr)
	if _, err := os.Stat(marker); err == nil || code != 126 {
		t.Fatalf("exit = %d, ran = %v, want 126 and the command not run (stderr=%s)", code, err == nil, stderr.String())
	}
	receipts := enforceReceipts(t, dataDir)
	if len(receipts) != 1 {
		t.Fatalf("a refused command left %d receipts, want only its one denial: %+v", len(receipts), receipts)
	}
	for _, receipt := range receipts {
		metadata := receipt.Request.Metadata
		if receipt.Verdict != contracts.WorkstationVerdictDeny {
			t.Fatalf("a refused command left a %s receipt for %s", receipt.Verdict, receipt.Request.Target)
		}
		if metadata["call_id"] == "" || metadata["call_receipts"] != "1" || metadata["call_verdict"] != contracts.WorkstationVerdictDeny || metadata["argv_sha256"] == "" {
			t.Fatalf("receipt does not bind its call: %+v", metadata)
		}
	}

	// The audit of that directory counts no allowed action.
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "audit", "scope", "--input", filepath.Join(dataDir, "enforce-receipts"), "--data-dir", dataDir, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("audit scope exit = %d stderr = %s", code, stderr.String())
	}
	var report workstation.ScopeAuditReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("scope audit JSON: %v\n%s", err, stdout.String())
	}
	if report.Summary.AllowedActions != 0 || report.Summary.DeniedActions != 1 {
		t.Fatalf("audit of a refused command: allowed=%d denied=%d, want 0 and 1", report.Summary.AllowedActions, report.Summary.DeniedActions)
	}

	// A command that runs keeps every receipt, each bound to the one run.
	allowedDir := filepath.Join(t.TempDir(), "helm")
	stdout.Reset()
	stderr.Reset()
	if code := Run(enforceArgs(allowedDir, allow, "--class", "shell-operate", "--", "curl", "https://api.github.com/zen"), &stdout, &stderr); code != 0 {
		t.Fatalf("allowed command exit = %d stderr = %s", code, stderr.String())
	}
	allowed := enforceReceipts(t, allowedDir)
	if len(allowed) != 2 {
		t.Fatalf("an allowed command left %d receipts, want the declared and the network decision", len(allowed))
	}
	callID := allowed[0].Request.Metadata["call_id"]
	for _, receipt := range allowed {
		metadata := receipt.Request.Metadata
		if callID == "" || metadata["call_id"] != callID || metadata["call_receipts"] != strconv.Itoa(len(allowed)) || metadata["call_verdict"] != contracts.WorkstationVerdictAllow {
			t.Fatalf("receipts of one run do not share its call binding: %+v", metadata)
		}
	}
}

// A signal that ends the command is reported as a shell reports it.
func TestWorkstationEnforceReportsTheSignalThatEndedTheCommand(t *testing.T) {
	allow := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "self-terminating"), []byte("#!/bin/sh\nkill -TERM $$\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	clearEnforceEnvironment(t)
	var stdout, stderr bytes.Buffer
	if code := Run(enforceArgs(filepath.Join(t.TempDir(), "helm"), allow, "--class", "shell-operate", "--", "self-terminating"), &stdout, &stderr); code != 128+15 {
		t.Fatalf("exit = %d, want 143 for a command ended by SIGTERM (stderr=%s)", code, stderr.String())
	}
}

// audit scope writes its report into a directory of its own, as workstation
// evidence does: a used one is refused before anything is written, so a link
// planted in it is never written through.
func TestAuditScopeRefusesAnOutputDirectoryThatIsNotEmpty(t *testing.T) {
	dir, dataDir := receiptInputs(t)
	input := filepath.Join(dir, "signed.json")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatal(err)
	}
	keep := func(name string) string {
		path := filepath.Join(outside, name)
		if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	out := filepath.Join(t.TempDir(), "audit")
	if err := os.MkdirAll(filepath.Join(out, "scope-audit-evidencepack", "12_REPORTS"), 0o750); err != nil {
		t.Fatal(err)
	}
	markdown, packMarkdown := keep("scope-audit.md"), keep("pack-scope-audit.md")
	if err := os.Link(markdown, filepath.Join(out, "scope-audit.md")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if err := os.Link(packMarkdown, filepath.Join(out, "scope-audit-evidencepack", "12_REPORTS", "scope-audit.md")); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "audit", "scope", "--input", input, "--data-dir", dataDir, "--out", out, "--evidence-pack"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "not empty") {
		t.Fatalf("audit scope into a used directory: exit = %d stderr = %s, want 1 and a refusal that says it is not empty", code, stderr.String())
	}
	for _, path := range []string{markdown, packMarkdown} {
		if data, _ := os.ReadFile(path); string(data) != "keep" {
			t.Fatalf("%s was written through a hard link: %q", path, data)
		}
	}

	// A new directory is written in full.
	fresh := filepath.Join(t.TempDir(), "fresh")
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "audit", "scope", "--input", input, "--data-dir", dataDir, "--out", fresh, "--evidence-pack"}, &stdout, &stderr); code != 0 {
		t.Fatalf("audit scope into a new directory: exit = %d stderr = %s", code, stderr.String())
	}
	for _, rel := range []string{"scope-audit.json", "scope-audit.md", "evidence-refs.json", "scope-audit-evidencepack/00_INDEX.json", "scope-audit-evidencepack/12_REPORTS/scope-audit.md"} {
		if _, err := os.Stat(filepath.Join(fresh, rel)); err != nil {
			t.Fatalf("expected %s: %v", rel, err)
		}
	}
}

// audit scope has nothing to report on when no input is left to count: an
// empty input, or one in which no signature holds, is refused rather than
// reported as a scope with no actions.
func TestAuditScopeRefusesAnInputWithNothingToCount(t *testing.T) {
	dir, dataDir := receiptInputs(t)
	onlyBad := t.TempDir()
	for _, name := range []string{"unsigned.json", "tampered.json"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(onlyBad, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, input, stderr string
	}{
		{"empty directory", t.TempDir(), "no workstation receipt"},
		{"no signature holds", onlyBad, "signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run([]string{"helm-ai-kernel", "audit", "scope", "--input", tc.input, "--data-dir", dataDir, "--json"}, &stdout, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), tc.stderr) || stdout.Len() != 0 {
				t.Fatalf("exit = %d stdout = %s stderr = %s, want 1, no report and %q", code, stdout.String(), stderr.String(), tc.stderr)
			}
		})
	}
}
