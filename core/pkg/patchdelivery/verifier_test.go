package patchdelivery

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ── shared git fixtures ─────────────────────────────────────────────────────

func newGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "test@helm.local"},
		{"config", "user.name", "helm-test"},
		// The CRLF fidelity tests depend on git not normalizing line endings
		// out from under them.
		{"config", "core.autocrlf", "false"},
	} {
		runGitT(t, dir, args...)
	}
	writeFile(t, filepath.Join(dir, "seed.txt"), []byte("seed\n"))
	runGitT(t, dir, "add", "-A")
	runGitT(t, dir, "commit", "-q", "-m", "seed")
	return dir
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func runGitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func headSHA(t *testing.T, repo string) string {
	t.Helper()
	return strings.TrimSpace(runGitT(t, repo, "rev-parse", "HEAD"))
}

// capturePatch produces a patch the same way core/pkg/worktree does: mutate an
// isolated checkout of baseSHA, then diff it against that base with --binary.
func capturePatch(t *testing.T, repo, baseSHA string, mutate func(dir string)) []byte {
	t.Helper()
	tree := filepath.Join(t.TempDir(), "capture")
	runGitT(t, repo, "worktree", "add", "--detach", tree, baseSHA)
	t.Cleanup(func() {
		_ = exec.Command("git", "-C", repo, "worktree", "remove", "--force", tree).Run()
		_ = exec.Command("git", "-C", repo, "worktree", "prune").Run()
	})

	mutate(tree)
	runGitT(t, tree, "add", "-A")

	cmd := exec.Command("git", "diff", "--cached", "--binary", baseSHA)
	cmd.Dir = tree
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("capture patch: %v: %s", err, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatal("capture produced an empty patch")
	}
	return stdout.Bytes()
}

func boolPtr(b bool) *bool { return &b }

func describeTriState(p *bool) string {
	if p == nil {
		return "nil"
	}
	if *p {
		return "true"
	}
	return "false"
}

// passingGate and failingGate use git itself so the tests need no extra binary
// beyond the one the package already requires.
func passingGate() GateSpec {
	return GateSpec{Name: "git-version", Command: "git", Args: []string{"--version"}}
}

func failingGate() GateSpec {
	return GateSpec{Name: "bad-ref", Command: "git", Args: []string{"rev-parse", "--verify", "refs/heads/no-such-ref-xyz"}}
}

// ── the tri-state matrix ────────────────────────────────────────────────────

// The whole package rests on telling PROVEN-FALSE apart from UNKNOWN apart from
// TRUE-BUT-UNCHECKED. If these three ever collapse into one boolean, an
// override that should be impossible becomes possible.
func TestFinalVerifyTriState(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		// setup returns repoRoot, patch, baseSHA, gates
		setup          func(t *testing.T) (string, []byte, string, []GateSpec)
		wantApplied    *bool
		wantGates      *bool
		reasonContains string
	}{
		{
			name: "applies to a clean base with no gates configured",
			setup: func(t *testing.T) (string, []byte, string, []GateSpec) {
				repo := newGitRepo(t)
				base := headSHA(t, repo)
				patch := capturePatch(t, repo, base, func(dir string) {
					writeFile(t, filepath.Join(dir, "added.txt"), []byte("hello\n"))
				})
				return repo, patch, base, nil
			},
			wantApplied: boolPtr(true),
			wantGates:   nil,
			// Must not claim gates passed.
			reasonContains: "no gates configured",
		},
		{
			name: "applies and configured gates pass",
			setup: func(t *testing.T) (string, []byte, string, []GateSpec) {
				repo := newGitRepo(t)
				base := headSHA(t, repo)
				patch := capturePatch(t, repo, base, func(dir string) {
					writeFile(t, filepath.Join(dir, "added.txt"), []byte("hello\n"))
				})
				return repo, patch, base, []GateSpec{passingGate()}
			},
			wantApplied:    boolPtr(true),
			wantGates:      boolPtr(true),
			reasonContains: "gate(s) passed",
		},
		{
			name: "applies but a gate fails",
			setup: func(t *testing.T) (string, []byte, string, []GateSpec) {
				repo := newGitRepo(t)
				base := headSHA(t, repo)
				patch := capturePatch(t, repo, base, func(dir string) {
					writeFile(t, filepath.Join(dir, "added.txt"), []byte("hello\n"))
				})
				return repo, patch, base, []GateSpec{passingGate(), failingGate()}
			},
			wantApplied:    boolPtr(true),
			wantGates:      boolPtr(false),
			reasonContains: `gate "bad-ref" failed`,
		},
		{
			name: "a gate that cannot be executed has not passed",
			setup: func(t *testing.T) (string, []byte, string, []GateSpec) {
				repo := newGitRepo(t)
				base := headSHA(t, repo)
				patch := capturePatch(t, repo, base, func(dir string) {
					writeFile(t, filepath.Join(dir, "added.txt"), []byte("hello\n"))
				})
				return repo, patch, base, []GateSpec{{
					Name: "missing-binary", Command: "helm-delivery-no-such-binary-xyz",
				}}
			},
			wantApplied: boolPtr(true),
			wantGates:   boolPtr(false),
			// Honest wording: it did not pass, but it did not "fail" on merit.
			reasonContains: "could not be executed",
		},
		{
			name: "PROVEN conflict when the patch cannot apply to the given base",
			setup: func(t *testing.T) (string, []byte, string, []GateSpec) {
				repo := newGitRepo(t)
				base1 := headSHA(t, repo)
				// A patch that edits seed.txt from its base1 content.
				patch := capturePatch(t, repo, base1, func(dir string) {
					writeFile(t, filepath.Join(dir, "seed.txt"), []byte("seed\nfrom base1\n"))
				})
				// Move the file out from under it and verify against the new base.
				writeFile(t, filepath.Join(repo, "seed.txt"), []byte("totally different content\n"))
				runGitT(t, repo, "add", "-A")
				runGitT(t, repo, "commit", "-q", "-m", "divergent")
				return repo, patch, headSHA(t, repo), nil
			},
			wantApplied:    boolPtr(false),
			wantGates:      nil,
			reasonContains: "does not apply to a clean base",
		},
		{
			name: "UNKNOWN when no base sha was recorded",
			setup: func(t *testing.T) (string, []byte, string, []GateSpec) {
				repo := newGitRepo(t)
				return repo, []byte("irrelevant"), "", nil
			},
			wantApplied:    nil,
			wantGates:      nil,
			reasonContains: "no base sha recorded; cannot verify against a clean base",
		},
		{
			name: "UNKNOWN when the base cannot be materialized",
			setup: func(t *testing.T) (string, []byte, string, []GateSpec) {
				repo := newGitRepo(t)
				return repo, []byte("irrelevant"), "0000000000000000000000000000000000000000", nil
			},
			wantApplied:    nil,
			wantGates:      nil,
			reasonContains: "could not materialize a clean base",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			repo, patch, base, gates := tc.setup(t)

			rec, err := FinalVerify(context.Background(), repo, patch, base, gates)
			if err != nil {
				t.Fatalf("FinalVerify returned an error instead of a record: %v", err)
			}
			if !rec.Attempted {
				t.Error("Attempted = false; every call that produces a record attempted verification")
			}
			if describeTriState(rec.AppliedCleanly) != describeTriState(tc.wantApplied) {
				t.Errorf("AppliedCleanly = %s, want %s (reason: %s)",
					describeTriState(rec.AppliedCleanly), describeTriState(tc.wantApplied), rec.Reason)
			}
			if describeTriState(rec.GatesPassed) != describeTriState(tc.wantGates) {
				t.Errorf("GatesPassed = %s, want %s (reason: %s)",
					describeTriState(rec.GatesPassed), describeTriState(tc.wantGates), rec.Reason)
			}
			if !strings.Contains(rec.Reason, tc.reasonContains) {
				t.Errorf("Reason = %q, want it to contain %q", rec.Reason, tc.reasonContains)
			}
		})
	}
}

// "no gates configured" must never be reported as "gates passed" — that would
// manufacture evidence that does not exist.
func TestNoGatesConfiguredIsNotReportedAsPassed(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	base := headSHA(t, repo)
	patch := capturePatch(t, repo, base, func(dir string) {
		writeFile(t, filepath.Join(dir, "added.txt"), []byte("hello\n"))
	})

	rec, err := FinalVerify(context.Background(), repo, patch, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.GatesPassed != nil {
		t.Fatalf("GatesPassed = %v, want nil for a run with no gates configured", *rec.GatesPassed)
	}
	if strings.Contains(rec.Reason, "gate(s) passed") {
		t.Fatalf("reason claims gates passed when none were configured: %q", rec.Reason)
	}
	if rec.AppliedCleanly == nil || !*rec.AppliedCleanly {
		t.Fatalf("AppliedCleanly = %s, want true", describeTriState(rec.AppliedCleanly))
	}
}

// The verification tree must hold the patch's bytes exactly, including CRLF and
// binary content. A gate is used as the observer because the tree is torn down
// before FinalVerify returns.
func TestFinalVerifyRoundTripsCRLFAndBinary(t *testing.T) {
	t.Parallel()
	cmp, err := exec.LookPath("cmp")
	if err != nil {
		t.Skip("cmp not available; skipping byte-fidelity gate")
	}

	crlf := []byte("alpha\r\nbeta\r\ngamma\r\n")
	binary := []byte{0x00, 0xff, 0xfe, 0x0d, 0x41, 0x00, 0x90}

	for _, tc := range []struct {
		name    string
		file    string
		content []byte
	}{
		{"crlf", "crlf.txt", crlf},
		{"binary", "blob.bin", binary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			repo := newGitRepo(t)
			base := headSHA(t, repo)
			patch := capturePatch(t, repo, base, func(dir string) {
				writeFile(t, filepath.Join(dir, tc.file), tc.content)
			})

			// A reference copy outside the verification tree; the gate proves the
			// applied file is byte-identical to it.
			reference := filepath.Join(t.TempDir(), "reference")
			writeFile(t, reference, tc.content)

			rec, err := FinalVerify(context.Background(), repo, patch, base, []GateSpec{{
				Name:    "byte-fidelity",
				Command: cmp,
				Args:    []string{"-s", tc.file, reference},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if rec.AppliedCleanly == nil || !*rec.AppliedCleanly {
				t.Fatalf("AppliedCleanly = %s: %s", describeTriState(rec.AppliedCleanly), rec.Reason)
			}
			if rec.GatesPassed == nil || !*rec.GatesPassed {
				t.Fatalf("byte-fidelity gate did not pass, so the patch did not round-trip: %s", rec.Reason)
			}
		})
	}
}

// Verification must never touch the live tree — that is what makes it safe to
// run before a mutation is authorized.
func TestFinalVerifyLeavesLiveTreeUntouched(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	base := headSHA(t, repo)
	patch := capturePatch(t, repo, base, func(dir string) {
		writeFile(t, filepath.Join(dir, "added.txt"), []byte("hello\n"))
	})

	if _, err := FinalVerify(context.Background(), repo, patch, base, []GateSpec{passingGate()}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(repo, "added.txt")); !os.IsNotExist(err) {
		t.Error("verification leaked its patch into the live tree")
	}
	if status := strings.TrimSpace(runGitT(t, repo, "status", "--porcelain")); status != "" {
		t.Errorf("live tree is dirty after verification:\n%s", status)
	}
}

func TestFinalVerifyRequiresRepoRoot(t *testing.T) {
	t.Parallel()
	if _, err := FinalVerify(context.Background(), "", nil, "abc", nil); err == nil {
		t.Fatal("expected an error for an empty repo root")
	}
}

// Reasons are copied into receipts and EvidencePacks, so a credential quoted in
// an error message would be persisted into signed evidence.
func TestRedactSecretsScrubsTokensButKeepsGitSHAs(t *testing.T) {
	t.Parallel()
	sha := "1f0c9d2e4b6a8c0e2f4a6b8d0c2e4f6a8b0d2c4e"

	for _, tc := range []struct {
		name string
		in   string
		gone string
		kept string
	}{
		{"anthropic key", "auth failed for sk-ant-api03-AAAABBBBCCCCDDDD", "sk-ant-api03", ""},
		{"github pat", "remote rejected: ghp_ABCDEFGHIJKLMNOPQRST0123", "ghp_ABCDEFGHIJKLMNOPQRST0123", ""},
		{"github fine-grained", "token github_pat_11ABCDEFG0123456789abc denied", "github_pat_11ABCDEFG", ""},
		{"slack token", "xoxb-1234567890-abcdefghij failed", "xoxb-1234567890", ""},
		{"aws key", "AKIAIOSFODNN7EXAMPLE is invalid", "AKIAIOSFODNN7EXAMPLE", ""},
		{"bearer", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz", ""},
		{"assignment", "config had password=hunter2supersecret", "hunter2supersecret", ""},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----", "BEGIN RSA PRIVATE KEY", ""},
		{"git sha survives", "patch does not apply to " + sha, "", sha},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := redactSecrets(tc.in)
			if tc.gone != "" && strings.Contains(got, tc.gone) {
				t.Errorf("secret survived redaction: %q still contains %q", got, tc.gone)
			}
			if tc.kept != "" && !strings.Contains(got, tc.kept) {
				t.Errorf("redaction destroyed evidence: %q no longer contains %q", got, tc.kept)
			}
		})
	}
}
