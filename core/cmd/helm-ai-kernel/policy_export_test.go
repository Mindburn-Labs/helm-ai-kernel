package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyExportCedarViewIsDeterministicAndReadOnly(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "deny-first.json")
	tmpl := getTemplate("deny-first")
	data, err := json.MarshalIndent(tmpl, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}

	code1, out1, err1 := runCLI(t, "policy", "export", "--dialect", "cedar", "--file", src)
	if code1 != 0 {
		t.Fatalf("code=%d stderr=%s", code1, err1)
	}
	code2, out2, err2 := runCLI(t, "policy", "export", "--dialect", "cedar", "--file", src)
	if code2 != 0 {
		t.Fatalf("second export code=%d stderr=%s", code2, err2)
	}
	if out1 != out2 {
		t.Fatalf("export was not deterministic\n%s\n%s", out1, out2)
	}
	if !strings.Contains(out1, "Not source of truth") {
		t.Fatalf("missing view disclaimer:\n%s", out1)
	}
	if !strings.Contains(out1, "permit") || !strings.Contains(out1, "forbid") {
		t.Fatalf("cedar view missing permit/forbid:\n%s", out1)
	}
	after, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("policy export mutated the source file")
	}
}

func TestPolicyExportJSONStillWorks(t *testing.T) {
	code, stdout, stderr := runCLI(t, "policy", "export", "--dialect", "opa", "--format=json")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	var report policyExportReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout)
	}
	if report.Schema != policyExportSchema {
		t.Fatalf("schema=%q", report.Schema)
	}
	if report.SourceOfTruth {
		t.Fatal("export must not claim source of truth")
	}
	if report.Authoritative != "helm_policy" {
		t.Fatalf("authoritative=%q", report.Authoritative)
	}
	if report.Dialect != "opa" {
		t.Fatalf("dialect=%q", report.Dialect)
	}
	if !strings.Contains(report.Document, "package helm.policy.view") {
		t.Fatalf("missing opa document: %s", report.Document)
	}
	if !strings.Contains(report.Document, "default allow := false") {
		t.Fatalf("opa view must stay fail-closed: %s", report.Document)
	}
}

func TestPolicyExportUnknownDialectAndFormat(t *testing.T) {
	code, stdout, stderr := runCLI(t, "policy", "export", "--dialect", "rego")
	if code != 2 {
		t.Fatalf("bad dialect code=%d", code)
	}
	assertCleanStdout(t, stdout)
	if !strings.Contains(stderr, "cedar") {
		t.Fatalf("stderr=%q", stderr)
	}
	code, stdout, stderr = runCLI(t, "policy", "export", "--dialect", "cedar", "--format=yaml")
	if code != 2 {
		t.Fatalf("bad format code=%d", code)
	}
	assertCleanStdout(t, stdout)
	if !strings.Contains(stderr, "expected text|json") {
		t.Fatalf("stderr=%q", stderr)
	}
}
