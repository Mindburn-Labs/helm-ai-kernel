package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/translog"
)

func runLogCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(append([]string{"helm-ai-kernel"}, args...), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestTranslogCLIRoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Append eight receipt hashes.
	for i := 0; i < 8; i++ {
		receiptHash := sha256.Sum256([]byte(fmt.Sprintf("receipt-%d", i)))
		code, out, errOut := runLogCLI(t, "log", "append",
			"--leaf-hash", hex.EncodeToString(receiptHash[:]),
			"--data-dir", dir)
		if code != 0 {
			t.Fatalf("append %d failed (%d): %s", i, code, errOut)
		}
		var resp struct {
			LeafIndex uint64 `json:"leaf_index"`
			TreeSize  uint64 `json:"tree_size"`
		}
		if err := json.Unmarshal([]byte(out), &resp); err != nil {
			t.Fatalf("append output not JSON: %v", err)
		}
		if resp.LeafIndex != uint64(i) || resp.TreeSize != uint64(i+1) {
			t.Fatalf("append %d: got index %d size %d", i, resp.LeafIndex, resp.TreeSize)
		}
	}

	// STH over the full tree.
	code, out, errOut := runLogCLI(t, "log", "sth", "--data-dir", dir)
	if code != 0 {
		t.Fatalf("sth failed (%d): %s", code, errOut)
	}
	var sth translog.SignedTreeHead
	if err := json.Unmarshal([]byte(out), &sth); err != nil {
		t.Fatalf("sth output not JSON: %v", err)
	}
	if sth.TreeSize != 8 || sth.Signature == "" || sth.LogID == "" {
		t.Fatalf("unexpected STH: %+v", sth)
	}
	if err := translog.VerifyTreeHead(&sth, sth.PublicKey); err != nil {
		t.Fatalf("CLI STH does not verify: %v", err)
	}

	// Inclusion proof for leaf 3 and offline verification.
	code, out, errOut = runLogCLI(t, "log", "prove", "--index", "3", "--data-dir", dir)
	if code != 0 {
		t.Fatalf("prove failed (%d): %s", code, errOut)
	}
	incPath := filepath.Join(dir, "inclusion.json")
	if err := os.WriteFile(incPath, []byte(out), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = runLogCLI(t, "log", "verify-inclusion", "--proof", incPath, "--root", sth.RootHash)
	if code != 0 {
		t.Fatalf("verify-inclusion failed (%d): %s", code, errOut)
	}
	if !strings.HasPrefix(out, "OK:") {
		t.Fatalf("unexpected verify-inclusion output: %s", out)
	}

	// Negative: verification against a tampered root must fail.
	badRoot := flipHexNibble(sth.RootHash[0]) + sth.RootHash[1:]
	code, _, errOut = runLogCLI(t, "log", "verify-inclusion", "--proof", incPath, "--root", badRoot)
	if code != 1 {
		t.Fatalf("verify-inclusion with tampered root: exit %d, want 1 (%s)", code, errOut)
	}

	// Consistency proof 5 -> 8 and offline verification.
	code, out, errOut = runLogCLI(t, "log", "prove", "--old-size", "5", "--new-size", "8", "--data-dir", dir)
	if code != 0 {
		t.Fatalf("prove consistency failed (%d): %s", code, errOut)
	}
	consPath := filepath.Join(dir, "consistency.json")
	if err := os.WriteFile(consPath, []byte(out), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = runLogCLI(t, "log", "verify-consistency", "--proof", consPath)
	if code != 0 {
		t.Fatalf("verify-consistency failed (%d): %s", code, errOut)
	}
	if !strings.HasPrefix(out, "OK:") {
		t.Fatalf("unexpected verify-consistency output: %s", out)
	}

	// Negative: equivocation — a different root claimed at the same new
	// size must fail consistency verification.
	code, _, errOut = runLogCLI(t, "log", "verify-consistency", "--proof", consPath, "--new-root", badRoot)
	if code != 1 {
		t.Fatalf("verify-consistency with equivocating root: exit %d, want 1 (%s)", code, errOut)
	}
}

func TestTranslogCLIUsageErrors(t *testing.T) {
	if code, _, _ := runLogCLI(t, "log"); code != 2 {
		t.Fatalf("bare log: exit %d, want 2", code)
	}
	if code, _, _ := runLogCLI(t, "log", "unknown"); code != 2 {
		t.Fatalf("unknown subcommand: exit %d, want 2", code)
	}
	if code, _, _ := runLogCLI(t, "log", "append", "--data-dir", t.TempDir()); code != 2 {
		t.Fatalf("append without --leaf-hash: exit %d, want 2", code)
	}
	if code, _, _ := runLogCLI(t, "log", "prove", "--data-dir", t.TempDir()); code != 2 {
		t.Fatalf("prove without mode: exit %d, want 2", code)
	}
	if code, _, _ := runLogCLI(t, "log", "verify-inclusion"); code != 2 {
		t.Fatalf("verify-inclusion without flags: exit %d, want 2", code)
	}
}

func flipHexNibble(c byte) string {
	if c == '0' {
		return "1"
	}
	return "0"
}
