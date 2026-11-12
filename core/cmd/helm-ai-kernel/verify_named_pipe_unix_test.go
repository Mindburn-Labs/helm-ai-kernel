//go:build unix

package main

// quantum_posture: these tests sign a conformance report with a throwaway
// Ed25519 key only to reach the pack reads under test; they make no
// post-quantum or classical signature assurance.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

// `verify` adds the layout check and the conformance signature check to the
// verifier library's checks, and both read pack files by path. A named pipe
// in place of 00_INDEX.json or 01_SCORE.json blocked the command there.
func TestVerifyCLIDoesNotBlockOnANamedPipe(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	for _, rel := range []string{"00_INDEX.json", "01_SCORE.json", "07_ATTESTATIONS/conformance_report.sig"} {
		t.Run(rel, func(t *testing.T) {
			packDir := writeCLIPack(t, dataDir, cliPack{})
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conform.SignReport(packDir, "sha256:policy", "sha256:schemas", "test-signer", func(data []byte) (string, error) {
				return hex.EncodeToString(ed25519.Sign(priv, data)), nil
			}); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HELM_VERIFY_PUBLIC_KEY_HEX", hex.EncodeToString(pub))
			fifo := filepath.Join(packDir, filepath.FromSlash(rel))
			if err := os.Remove(fifo); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			done := make(chan int, 1)
			var stdout, stderr bytes.Buffer
			go func() { done <- runVerifyCmd([]string{"--allow-self-attested", packDir}, &stdout, &stderr) }()
			select {
			case code := <-done:
				if code != 1 {
					t.Fatalf("exit=%d, want 1 for a pack with a named pipe in it\n%s%s", code, stdout.String(), stderr.String())
				}
			case <-time.After(10 * time.Second):
				for i := 0; i < 6; i++ {
					if fd, err := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
						_ = syscall.Close(fd)
					}
					time.Sleep(50 * time.Millisecond)
				}
				t.Fatalf("verify blocked on the named pipe %s", rel)
			}
		})
	}
}

// The --require-eidas and --require-tee checks read anchors and receipts by
// path, and a named pipe there blocked `verify`.
func TestVerifyFlagChecksDoNotBlockOnANamedPipe(t *testing.T) {
	for _, tc := range []struct {
		rel   string
		check func(dir string) []verifier.CheckResult
	}{
		{"02_PROOFGRAPH/anchors/a.json", func(dir string) []verifier.CheckResult { return checkEIDASAnchorMetadata(dir, time.Hour) }},
		{"receipts/r.json", func(dir string) []verifier.CheckResult { return checkTEEAttestations(dir, "any") }},
	} {
		t.Run(tc.rel, func(t *testing.T) {
			dir := t.TempDir()
			fifo := filepath.Join(dir, filepath.FromSlash(tc.rel))
			if err := os.MkdirAll(filepath.Dir(fifo), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			done := make(chan []verifier.CheckResult, 1)
			go func() { done <- tc.check(dir) }()
			select {
			case results := <-done:
				refused := false
				for _, result := range results {
					if result.Pass {
						t.Fatalf("%s passed on a named pipe: %s", result.Name, result.Detail)
					}
					if strings.Contains(result.Reason, "not a regular file") {
						refused = true
					}
				}
				if !refused {
					t.Fatalf("no result says the named pipe is not a regular file: %+v", results)
				}
			case <-time.After(10 * time.Second):
				if fd, err := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = syscall.Close(fd)
				}
				t.Fatalf("the check blocked on the named pipe %s", tc.rel)
			}
		})
	}
}
