package worktree

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "test@helm.local"},
		{"config", "user.name", "helm-test"},
		// Leave line endings exactly as authored; the CRLF test depends on git
		// not normalizing them out from under us.
		{"config", "core.autocrlf", "false"},
	} {
		runGit(t, dir, args...)
	}
	write(t, filepath.Join(dir, "seed.txt"), []byte("seed\n"))
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-q", "-m", "seed")
	return dir
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func newTree(t *testing.T, repo string) *Envelope {
	t.Helper()
	env, err := Create(Options{
		RepoRoot:    repo,
		RunID:       "run01",
		AttemptID:   "a01",
		RuntimeRoot: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = env.Dispose() })
	return env
}

// applyToCleanBase re-applies a captured diff to a fresh checkout of the base
// and returns that checkout, proving the patch survives a clean tree.
func applyToCleanBase(t *testing.T, repo, baseSHA string, diff []byte) string {
	t.Helper()
	verify := filepath.Join(t.TempDir(), "verify")
	runGit(t, repo, "worktree", "add", "--detach", verify, baseSHA)
	t.Cleanup(func() {
		_ = exec.Command("git", "-C", repo, "worktree", "remove", "--force", verify).Run()
	})
	apply := exec.Command("git", "apply", "--binary", "-")
	apply.Dir = verify
	apply.Stdin = bytes.NewReader(diff)
	if out, err := apply.CombinedOutput(); err != nil {
		t.Fatalf("captured diff did not re-apply to a clean base: %v: %s", err, out)
	}
	return verify
}

// The property the whole evidence chain rests on: what the tree records as the
// work product must be the bytes that were written. A line scanner in the
// capture path rewrites a lone \r into \n and silently corrupts CRLF content,
// so this fails loudly if capture ever grows one.
func TestCaptureDiffPreservesCRLF(t *testing.T) {
	repo := newRepo(t)
	env := newTree(t, repo)

	crlf := []byte("alpha\r\nbeta\r\ngamma\r\n")
	write(t, filepath.Join(env.Tree, "crlf.txt"), crlf)

	diff, err := env.CaptureDiff()
	if err != nil {
		t.Fatalf("CaptureDiff: %v", err)
	}
	if !bytes.Contains(diff, []byte("alpha\r")) {
		t.Fatalf("carriage returns lost in capture; diff:\n%s", diff)
	}

	verify := applyToCleanBase(t, repo, env.BaseSHA, diff)
	got, err := os.ReadFile(filepath.Join(verify, "crlf.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, crlf) {
		t.Fatalf("round-trip mismatch:\n want %q\n  got %q", crlf, got)
	}
}

func TestCaptureDiffPreservesBinary(t *testing.T) {
	repo := newRepo(t)
	env := newTree(t, repo)

	// Not valid UTF-8; includes NUL and a bare \r.
	blob := []byte{0x00, 0xff, 0xfe, 0x0d, 0x41, 0x00, 0x90}
	write(t, filepath.Join(env.Tree, "blob.bin"), blob)

	diff, err := env.CaptureDiff()
	if err != nil {
		t.Fatalf("CaptureDiff: %v", err)
	}
	if !bytes.Contains(diff, []byte("GIT binary patch")) {
		t.Fatalf("expected a binary patch section; diff:\n%s", diff)
	}

	verify := applyToCleanBase(t, repo, env.BaseSHA, diff)
	got, err := os.ReadFile(filepath.Join(verify, "blob.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatalf("binary round-trip mismatch:\n want %v\n  got %v", blob, got)
	}
}

// The scoped HOME must not sit inside the tree, or the `git add -A` in capture
// would pull vendor credentials and session transcripts into the work product.
func TestScopedHomeIsOutsideTree(t *testing.T) {
	repo := newRepo(t)
	env := newTree(t, repo)

	if isWithin(env.HomeDir, env.Tree) {
		t.Fatalf("scoped HOME %q is inside the tree %q", env.HomeDir, env.Tree)
	}

	// Prove it behaviourally, not just by path arithmetic.
	write(t, filepath.Join(env.HomeDir, ".claude", ".credentials.json"),
		[]byte(`{"accessToken":"sk-ant-secret-value"}`))
	write(t, filepath.Join(env.Tree, "work.txt"), []byte("real work\n"))

	diff, err := env.CaptureDiff()
	if err != nil {
		t.Fatalf("CaptureDiff: %v", err)
	}
	if bytes.Contains(diff, []byte("sk-ant-secret-value")) {
		t.Fatal("scoped HOME credential leaked into the captured work product")
	}
	if !bytes.Contains(diff, []byte("real work")) {
		t.Fatalf("expected the real work in the diff; got:\n%s", diff)
	}
}

func TestEnvPlacesHarnessInsideScopedHome(t *testing.T) {
	repo := newRepo(t)
	env := newTree(t, repo)

	got := env.Env()
	if got["HOME"] != env.HomeDir {
		t.Fatalf("HOME = %q, want %q", got["HOME"], env.HomeDir)
	}
	for _, key := range []string{"HOME", "XDG_CONFIG_HOME", "CLAUDE_CONFIG_DIR", "CODEX_HOME"} {
		v, ok := got[key]
		if !ok {
			t.Errorf("%s not set", key)
			continue
		}
		if !isWithin(v, env.HomeDir) {
			t.Errorf("%s = %q is not inside the scoped home %q", key, v, env.HomeDir)
		}
	}
}

func TestCreateRejectsUnsafeIDs(t *testing.T) {
	repo := newRepo(t)
	runtime := t.TempDir()

	for _, tc := range []struct{ name, run, attempt string }{
		{"traversal in run id", "../escape", "a01"},
		{"traversal in attempt id", "run01", ".."},
		{"separator in attempt id", "run01", "a01/../.."},
		{"empty run id", "", "a01"},
		{"leading dot", ".hidden", "a01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Create(Options{
				RepoRoot: repo, RunID: tc.run, AttemptID: tc.attempt, RuntimeRoot: runtime,
			}); err == nil {
				t.Fatal("expected a refusal, got nil")
			} else if !strings.Contains(err.Error(), "safe path segment") {
				t.Fatalf("expected ErrUnsafeSegment, got %v", err)
			}
		})
	}
}

// A tree materialized inside the project would show up in the project's own git
// status and could be destroyed by a `git clean` in the live tree.
func TestCreateRejectsRuntimeRootInsideRepo(t *testing.T) {
	repo := newRepo(t)
	if _, err := Create(Options{
		RepoRoot:    repo,
		RunID:       "run01",
		AttemptID:   "a01",
		RuntimeRoot: filepath.Join(repo, ".helm-runtime"),
	}); err == nil {
		t.Fatal("expected a refusal for a runtime root inside the repo")
	} else if !strings.Contains(err.Error(), "inside repo root") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The live project tree must be untouched by isolated work — that is the whole
// isolation claim.
func TestLiveTreeUnaffected(t *testing.T) {
	repo := newRepo(t)
	env := newTree(t, repo)

	write(t, filepath.Join(env.Tree, "only-in-tree.txt"), []byte("x\n"))
	if _, err := env.CaptureDiff(); err != nil {
		t.Fatalf("CaptureDiff: %v", err)
	}

	if _, err := os.Stat(filepath.Join(repo, "only-in-tree.txt")); !os.IsNotExist(err) {
		t.Fatal("isolated work leaked into the live project tree")
	}
	if status := runGit(t, repo, "status", "--porcelain"); strings.TrimSpace(status) != "" {
		t.Fatalf("live tree is dirty after isolated work:\n%s", status)
	}
}

func TestDisposeIsIdempotent(t *testing.T) {
	repo := newRepo(t)
	env, err := Create(Options{
		RepoRoot: repo, RunID: "run01", AttemptID: "a01", RuntimeRoot: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := env.Dispose(); err != nil {
		t.Fatalf("first Dispose: %v", err)
	}
	if err := env.Dispose(); err != nil {
		t.Fatalf("second Dispose should be a no-op, got: %v", err)
	}
	if _, err := os.Stat(env.Tree); !os.IsNotExist(err) {
		t.Fatal("tree still present after Dispose")
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
