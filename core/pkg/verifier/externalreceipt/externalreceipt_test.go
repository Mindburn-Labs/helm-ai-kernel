package externalreceipt

import (
	"errors"
	iofs "io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence/externalhost"
)

func TestVerifyBundleNoFiles(t *testing.T) {
	report := VerifyBundle(t.TempDir())
	if report.Found {
		t.Fatalf("expected no chain files, got %#v", report)
	}
	if len(report.ChainFiles) != 0 || len(report.Checks) != 0 || len(report.ChainReports) != 0 {
		t.Fatalf("unexpected report contents: %#v", report)
	}
}

func TestVerifyBundleSuccessAndVerifierError(t *testing.T) {
	root := t.TempDir()
	hostDir := filepath.Join(root, "host_evidence")
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	badFile := filepath.Join(hostDir, "bad.jsonl")
	goodFile := filepath.Join(hostDir, "good.ndjson")
	for _, file := range []string{badFile, goodFile} {
		if err := os.WriteFile(file, []byte("{}"), 0600); err != nil {
			t.Fatalf("WriteFile %s: %v", file, err)
		}
	}

	restore := replaceHooks()
	defer restore()

	sentinel := errors.New("signature failed")
	receiptVerifyFile = func(path string, opts externalhost.VerifyOptions) (*externalhost.VerificationReport, error) {
		if !opts.RequireKey {
			t.Fatal("expected RequireKey")
		}
		if strings.Contains(path, "bad") {
			return nil, sentinel
		}
		return &externalhost.VerificationReport{
			Verified: true,
			Checks: []externalhost.CheckResult{
				{Name: "external_host:signature", Pass: true, Detail: "ok"},
			},
		}, nil
	}

	report := VerifyBundle(root)
	if !report.Found {
		t.Fatalf("expected bundle evidence, got %#v", report)
	}
	if len(report.ChainFiles) != 2 {
		t.Fatalf("expected two chain files, got %v", report.ChainFiles)
	}
	if len(report.ChainReports) != 1 {
		t.Fatalf("expected one successful report, got %#v", report.ChainReports)
	}
	if len(report.Checks) != 2 {
		t.Fatalf("expected verifier error and success check, got %#v", report.Checks)
	}
	if report.Checks[0].Name != "external_host:chain_file" || !strings.Contains(report.Checks[0].Reason, "host_evidence/bad.jsonl") {
		t.Fatalf("unexpected error check: %#v", report.Checks[0])
	}
	if report.Checks[1].Name != "host_evidence/good.ndjson:external_host:signature" || !report.Checks[1].Pass {
		t.Fatalf("unexpected success check: %#v", report.Checks[1])
	}
}

func TestFindChainFiles(t *testing.T) {
	root := t.TempDir()
	hostDir := filepath.Join(root, "host_evidence")
	legacyDir := filepath.Join(root, "11_HOST_EVIDENCE")
	if err := os.MkdirAll(filepath.Join(hostDir, "nested"), 0755); err != nil {
		t.Fatalf("MkdirAll host: %v", err)
	}
	if err := os.MkdirAll(legacyDir, 0755); err != nil {
		t.Fatalf("MkdirAll legacy: %v", err)
	}
	write := func(path string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
	}
	write(filepath.Join(hostDir, "alpha.json"))
	write(filepath.Join(hostDir, "beta.jsonl"))
	write(filepath.Join(hostDir, "correlation.json"))
	write(filepath.Join(hostDir, "verification.json"))
	write(filepath.Join(hostDir, "notes.txt"))
	write(filepath.Join(hostDir, "nested", "gamma.NDJSON"))
	write(filepath.Join(legacyDir, "delta.json"))

	got := FindChainFiles(root)
	want := []string{
		filepath.Join(legacyDir, "delta.json"),
		filepath.Join(hostDir, "alpha.json"),
		filepath.Join(hostDir, "beta.jsonl"),
		filepath.Join(hostDir, "nested", "gamma.NDJSON"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FindChainFiles mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestFindChainFilesSkipsStatAndWalkErrors(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "host_evidence"), []byte("not a dir"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if got := FindChainFiles(root); len(got) != 0 {
		t.Fatalf("expected non-directory evidence path to be skipped, got %v", got)
	}

	if err := os.Remove(filepath.Join(root, "host_evidence")); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "host_evidence"), 0755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	restore := replaceHooks()
	defer restore()

	receiptWalkDir = func(root string, fn iofs.WalkDirFunc) error {
		return fn(filepath.Join(root, "bad.jsonl"), nil, errors.New("walk failed"))
	}
	if got := FindChainFiles(root); len(got) != 0 {
		t.Fatalf("expected walk error entry to be skipped, got %v", got)
	}
}

func TestRelFallback(t *testing.T) {
	restore := replaceHooks()
	defer restore()

	receiptRel = func(string, string) (string, error) {
		return "", errors.New("rel failed")
	}
	if got := rel("root", "root/file.jsonl"); got != "root/file.jsonl" {
		t.Fatalf("expected fallback path, got %q", got)
	}
}

func replaceHooks() func() {
	originalStat := receiptStat
	originalWalkDir := receiptWalkDir
	originalRel := receiptRel
	originalVerifyFile := receiptVerifyFile
	return func() {
		receiptStat = originalStat
		receiptWalkDir = originalWalkDir
		receiptRel = originalRel
		receiptVerifyFile = originalVerifyFile
	}
}
