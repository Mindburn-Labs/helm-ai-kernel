package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func TestAuditScopeJSON(t *testing.T) {
	root := kernelRepoRoot(t)
	input := filepath.Join(root, "fixtures", "workstation", "reference", "receipts")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "audit", "scope", "--input", input, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("audit scope exit = %d stderr = %s", code, stderr.String())
	}
	var report workstation.ScopeAuditReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("scope audit JSON invalid: %v output=%s", err, stdout.String())
	}
	if report.ReportVersion != workstation.ScopeAuditReportVersion {
		t.Fatalf("report version = %q", report.ReportVersion)
	}
	if report.Summary.InputFiles == 0 || report.Summary.OutOfScopeAttempts == 0 {
		t.Fatalf("unexpected audit summary: %+v", report.Summary)
	}
	if !strings.Contains(stdout.String(), `"boundaries"`) {
		t.Fatalf("canonical JSON missing boundaries: %s", stdout.String())
	}
}

func TestAuditScopeArtifactsAndEvidencePack(t *testing.T) {
	root := kernelRepoRoot(t)
	input := filepath.Join(root, "fixtures", "workstation", "reference", "receipts")
	out := filepath.Join(t.TempDir(), "audit")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "audit", "scope", "--input", input, "--out", out, "--evidence-pack"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("audit scope out exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "Agent Scope Audit") || !strings.Contains(stdout.String(), "evidencepack:") {
		t.Fatalf("audit summary missing expected fields: %s", stdout.String())
	}
	for _, path := range []string{
		filepath.Join(out, "scope-audit.json"),
		filepath.Join(out, "scope-audit.md"),
		filepath.Join(out, "evidence-refs.json"),
		filepath.Join(out, "scope-audit-evidencepack", "00_INDEX.json"),
		filepath.Join(out, "scope-audit-evidencepack", "12_REPORTS", "scope-audit.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}
}

func TestAuditScopeErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "audit", "scope"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "--input is required") {
		t.Fatalf("missing input exit=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "audit", "scope", "--input", t.TempDir()}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "no workstation receipt JSON files found") {
		t.Fatalf("empty dir exit=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "audit", "scope", "--input", filepath.Join(t.TempDir(), "missing.json")}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "scope audit failed") {
		t.Fatalf("missing file exit=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "audit", "nope"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "Unknown audit command") {
		t.Fatalf("unknown subcommand exit=%d stderr=%s", code, stderr.String())
	}
}
