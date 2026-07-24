package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/riskenvelope"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/riskscan"
)

// writeTestScanPack scans a small synthetic workspace and returns the path to a
// risk-scan/v1 EvidencePack archive.
func writeTestScanPack(t *testing.T, dir string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{"mcpServers":{"prod":{"command":"deploy-production"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	claudeDir := filepath.Join(root, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{"permissionMode":"acceptEdits"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 6, 30, 16, 0, 0, 0, time.UTC)
	result, err := riskscan.ScanWithEvidence(root, riskscan.BuildOptions{
		Salt:   bytes.Repeat([]byte{0x08}, riskenvelope.SaltBytes),
		Cohort: riskenvelope.CohortUnknown,
		Now:    now,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	pack := filepath.Join(dir, "pack.tar")
	if err := riskscan.WriteEvidencePack(pack, result, nil, riskscan.EvidencePackOptions{DataDir: t.TempDir(), Now: now}); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	return pack
}

func TestCLI_VerifyScan_ArchiveAndDirectory(t *testing.T) {
	dir := t.TempDir()
	pack := writeTestScanPack(t, dir)

	// Archive input, routed through the top-level verify command to exercise dispatch.
	var stdout, stderr bytes.Buffer
	if rc := runVerifyCmd([]string{"scan", "--bundle", pack}, &stdout, &stderr); rc != 0 {
		t.Fatalf("archive rc=%d stderr=%s out=%s", rc, stderr.String(), stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("VERIFIED")) {
		t.Fatalf("expected VERIFIED in output, got %s", stdout.String())
	}

	// Directory input, using the same extraction the command performs internally.
	extracted := t.TempDir()
	if err := extractEvidenceArchive(pack, extracted); err != nil {
		t.Fatalf("extract: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if rc := runVerifyScanCmd([]string{extracted}, &stdout, &stderr); rc != 0 {
		t.Fatalf("directory rc=%d stderr=%s out=%s", rc, stderr.String(), stdout.String())
	}
}

func TestCLI_VerifyScan_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	pack := writeTestScanPack(t, dir)

	var stdout, stderr bytes.Buffer
	if rc := runVerifyScanCmd([]string{"--bundle", pack, "--json"}, &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	var res riskscan.EvidencePackVerification
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("decode result: %v (%s)", err, stdout.String())
	}
	if !res.Verified {
		t.Fatalf("expected verified, got %+v", res)
	}
}

// Byte-level tamper of an indexed artifact must surface as rc=1 with FAILED on
// stdout. The trailing-JSON case specifically is covered where the contract hash
// is computed, in riskscan.TestVerifyScanEvidenceSummaryRejectsTrailingData.
func TestCLI_VerifyScan_TamperedPackFails(t *testing.T) {
	dir := t.TempDir()
	pack := writeTestScanPack(t, dir)
	extracted := t.TempDir()
	if err := extractEvidenceArchive(pack, extracted); err != nil {
		t.Fatalf("extract: %v", err)
	}
	summary := filepath.Join(extracted, "04_EXPORTS", "source-projection-summary.json")
	data, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read summary artifact: %v", err)
	}
	if err := os.WriteFile(summary, append(data, []byte("\n{\"injected\":true}\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if rc := runVerifyScanCmd([]string{extracted}, &stdout, &stderr); rc != 1 {
		t.Fatalf("expected rc=1 for a tampered pack, got %d (out=%s)", rc, stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("FAILED")) {
		t.Fatalf("expected FAILED in output, got %s", stdout.String())
	}
}

func TestCLI_VerifyScan_UsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no bundle":         {},
		"two positionals":   {"a", "b"},
		"nonexistent path":  {filepath.Join(t.TempDir(), "missing")},
		"empty bundle flag": {"--bundle", ""},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if rc := runVerifyScanCmd(args, &stdout, &stderr); rc != 2 {
				t.Fatalf("expected rc=2, got %d (stderr=%s)", rc, stderr.String())
			}
		})
	}
}

// A verifiable bundle plus a stray positional must still be a usage error: with
// a real pack the command would otherwise succeed and silently ignore the extra.
func TestCLI_VerifyScan_RejectsExtraPositionalWithBundleFlag(t *testing.T) {
	dir := t.TempDir()
	pack := writeTestScanPack(t, dir)

	var stdout, stderr bytes.Buffer
	if rc := runVerifyScanCmd([]string{"--bundle", pack, "extra"}, &stdout, &stderr); rc != 2 {
		t.Fatalf("expected rc=2 for an unexpected extra argument, got %d (out=%s)", rc, stdout.String())
	}
}

func TestCLI_Verify_RejectsRiskScanPack(t *testing.T) {
	dir := t.TempDir()
	pack := writeTestScanPack(t, dir)
	extracted := t.TempDir()
	if err := extractEvidenceArchive(pack, extracted); err != nil {
		t.Fatalf("extract: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if rc := runVerifyCmd([]string{"--bundle", extracted}, &stdout, &stderr); rc != 2 {
		t.Fatalf("expected plain verify to reject a risk-scan pack with rc=2, got %d", rc)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("verify scan")) {
		t.Fatalf("expected redirect to `verify scan`, got %s", stderr.String())
	}
}
