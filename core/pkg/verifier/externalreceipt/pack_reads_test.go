package externalreceipt

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence/externalhost"
)

// F7: a host evidence file that is a symbolic link was read wherever the link
// pointed. Host files are read through an os.Root on the pack, so a link that
// leaves the pack is refused and named in a FAILED check.
func TestVerifyBundleRefusesHostFilesLinkedFromOutsideThePack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	for _, rel := range []string{"11_HOST_EVIDENCE/x/chain.json", "host_evidence/chain-verification.json"} {
		t.Run(rel, func(t *testing.T) {
			root := t.TempDir()
			outside := filepath.Join(t.TempDir(), "chain.json")
			if err := os.WriteFile(outside, []byte(`{"receipts":[{"receipt_id":"host-1"}]}`), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, link); err != nil {
				t.Fatal(err)
			}
			report := VerifyBundle(root)
			if !report.Found {
				t.Fatalf("a linked host file was reported as no host evidence: %#v", report)
			}
			refused := false
			for _, check := range report.Checks {
				if check.Status == externalhost.StatusVerified {
					t.Fatalf("%s VERIFIED on a file outside the pack", check.Name)
				}
				if check.Status == externalhost.StatusFailed && strings.Contains(check.Reason, rel) && strings.Contains(check.Reason, "outside the pack") {
					refused = true
				}
			}
			if !refused {
				t.Fatalf("no FAILED check refuses %s as outside the pack: %#v", rel, report.Checks)
			}
		})
	}
}

// N10: a file named like a report that holds a receipts member with nothing
// in it was failed with "parse JSONL line 1: unexpected end of JSON input".
// It is a receipt chain with no receipts, and the check says that.
func TestVerifyBundleSaysAReportWithAnEmptyReceiptsListHoldsNoReceipts(t *testing.T) {
	root := t.TempDir()
	writeHostFile(t, root, "host_evidence/chain-verification.json", `{"receipts":[],"results":[]}`)
	report := VerifyBundle(root)
	reasons := ""
	for _, check := range report.Checks {
		if check.Status == externalhost.StatusVerified {
			t.Fatalf("%s VERIFIED on a chain with no receipts", check.Name)
		}
		reasons += check.Reason + "\n"
	}
	if strings.Contains(reasons, "JSONL") || !strings.Contains(reasons, "no receipts") {
		t.Fatalf("reasons do not say the chain holds no receipts:\n%s", reasons)
	}
}

// N10: classifying a file named like a report read all of it. A file larger
// than the verifier reads is failed and the reason says why it was not read.
// The file is sparse, so it costs no disk.
func TestVerifyBundleNamesAReportFileTooLargeToRead(t *testing.T) {
	root := t.TempDir()
	path := writeHostFile(t, root, "host_evidence/chain-verification.json", "")
	if err := os.Truncate(path, 64<<20+1); err != nil {
		t.Fatal(err)
	}
	report := VerifyBundle(root)
	if len(report.Checks) != 1 || report.Checks[0].Status != externalhost.StatusFailed {
		t.Fatalf("checks = %#v, want one FAILED check", report.Checks)
	}
	if reason := report.Checks[0].Reason; !strings.Contains(reason, "host_evidence/chain-verification.json") || !strings.Contains(reason, "limit") {
		t.Fatalf("reason does not say the file is over the read limit: %q", reason)
	}
}

// A host evidence directory that is a symbolic link out of the pack was
// skipped like a missing one, so the pack read as carrying no host evidence.
// It is refused by name in a FAILED check.
func TestVerifyBundleRefusesAHostEvidenceDirectoryLinkedFromOutsideThePack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	for _, dir := range []string{"11_HOST_EVIDENCE", "host_evidence"} {
		t.Run(dir, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			if err := os.WriteFile(filepath.Join(outside, "chain.json"), []byte(`{"receipts":[{"receipt_id":"host-1"}]}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(root, dir)); err != nil {
				t.Fatal(err)
			}
			report := VerifyBundle(root)
			if !report.Found {
				t.Fatalf("a linked host evidence directory was reported as no host evidence: %#v", report)
			}
			refused := false
			for _, check := range report.Checks {
				if check.Status == externalhost.StatusVerified {
					t.Fatalf("%s VERIFIED on a directory outside the pack", check.Name)
				}
				if check.Status == externalhost.StatusFailed && strings.Contains(check.Reason, dir) && strings.Contains(check.Reason, "outside the pack") {
					refused = true
				}
			}
			if !refused {
				t.Fatalf("no FAILED check refuses %s as outside the pack: %#v", dir, report.Checks)
			}
		})
	}
}
