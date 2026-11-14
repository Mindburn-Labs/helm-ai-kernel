//go:build unix

package verifier

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// F7: a named pipe in the pack blocked the scan that opened it, so `verify`
// hung until something wrote to the pipe. A file that is not a regular file is
// refused before it is opened.
func TestChecksRefuseFilesThatAreNotRegularFiles(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rel   string
		check func(dir string) []CheckResult
	}{
		{"eu ai act scan", "12_REPORTS/in.json", func(dir string) []CheckResult { return []CheckResult{checkEUAIActEvidenceProfile(dir)} }},
		{"host evidence report", "11_HOST_EVIDENCE/x/chain-verification.json", func(dir string) []CheckResult { return checkHostEvidence(dir, VerifyOptions{}) }},
		{"host evidence chain", "11_HOST_EVIDENCE/x/chain.jsonl", func(dir string) []CheckResult { return checkHostEvidence(dir, VerifyOptions{}) }},
		{"connector evidence", "connector_evidence.json", func(dir string) []CheckResult { return []CheckResult{checkConnectorEvidence(dir)} }},
		{"determinism manifest", "02_PROOFGRAPH/determinism_manifest.json", func(dir string) []CheckResult { return []CheckResult{checkReplayDeterminism(dir)} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fifo := filepath.Join(dir, filepath.FromSlash(tc.rel))
			if err := os.MkdirAll(filepath.Dir(fifo), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			done := make(chan []CheckResult, 1)
			go func() { done <- tc.check(dir) }()
			var results []CheckResult
			select {
			case results = <-done:
			case <-time.After(10 * time.Second):
				// Unblock the reader so the goroutine ends with the test.
				if fd, err := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = syscall.Close(fd)
				}
				t.Fatalf("the check blocked on the named pipe %s", tc.rel)
			}
			failedOnPipe := false
			for _, result := range results {
				result = result.normalized()
				if result.Status == CheckVerified {
					t.Fatalf("%s VERIFIED on a named pipe: %s", result.Name, result.Detail)
				}
				if result.Status == CheckFailed && strings.Contains(result.Reason, "not a regular file") {
					failedOnPipe = true
				}
			}
			if !failedOnPipe {
				t.Fatalf("no FAILED result says the named pipe is not a regular file: %+v", results)
			}
		})
	}
}

// The seal check hashes every file 00_INDEX.json lists and reads the seal
// file, by path. A named pipe in place of an indexed file, of the index or of
// the seal blocked the whole verification there, after the checks that read
// through the pack root had already refused it.
func TestVerifyBundle_NamedPipesInSealedPathsDoNotBlock(t *testing.T) {
	for _, rel := range []string{"receipts/receipt-001.json", "00_INDEX.json", "07_ATTESTATIONS/evidence_pack.sig"} {
		t.Run(rel, func(t *testing.T) {
			dir := createValidBundleFixture(t)
			fifo := filepath.Join(dir, filepath.FromSlash(rel))
			if err := os.Remove(fifo); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			done := make(chan *VerifyReport, 1)
			go func() {
				report, _ := VerifyBundleWithOptions(dir, VerifyOptions{AllowSelfAttested: true})
				done <- report
			}()
			select {
			case report := <-done:
				if report == nil || report.Verified {
					t.Fatalf("report = %+v, want a FAILED report", report)
				}
				for _, check := range report.Checks {
					if check.Name == "evidence_pack_seal" && check.Status != CheckFailed {
						t.Fatalf("evidence_pack_seal = %s (%s), want FAILED", check.Status, check.Reason)
					}
				}
			case <-time.After(10 * time.Second):
				for i := 0; i < 4; i++ {
					if fd, err := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
						_ = syscall.Close(fd)
					}
					time.Sleep(50 * time.Millisecond)
				}
				t.Fatalf("verification blocked on the named pipe %s", rel)
			}
		})
	}
}
