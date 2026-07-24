package patchdelivery

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An unregistered mutation path is a release blocker. This test is the
// enforcement: add a way to write to a live tree without registering its fence
// and the build goes red.
func TestMutationPathsAreRegistered(t *testing.T) {
	registered := make(map[string]Fence)
	for _, r := range Paths() {
		registered[r.Name] = r.Fence
	}

	for _, required := range RequiredMutationPaths() {
		fence, ok := registered[required]
		if !ok {
			t.Errorf("mutation path %q is not registered; every path that can mutate a live project tree must declare its fence", required)
			continue
		}
		if !fence.Complete() {
			t.Errorf("mutation path %q has an incomplete fence (eligibility=%v preimage=%v); a path that can write to a live tree must route through both",
				required, fence.Eligibility, fence.Preimage)
		}
	}
}

func TestRegisterAndPathsAreOrdered(t *testing.T) {
	Register("zzz.test.path", Fence{Eligibility: true, Preimage: true, Note: "test"})
	Register("aaa.test.path", Fence{Eligibility: true, Preimage: true, Note: "test"})
	t.Cleanup(func() {
		mutationMu.Lock()
		delete(mutationPaths, "zzz.test.path")
		delete(mutationPaths, "aaa.test.path")
		mutationMu.Unlock()
	})

	got := Paths()
	var names []string
	for _, r := range got {
		names = append(names, r.Name)
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("Paths() is not ordered by name: %v", names)
		}
	}
	if !contains(names, "aaa.test.path") || !contains(names, "zzz.test.path") {
		t.Fatalf("registered paths missing from Paths(): %v", names)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func TestApplyProtectedAppliesAllOrNothing(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	base := headSHA(t, repo)
	patch := capturePatch(t, repo, base, func(dir string) {
		writeFile(t, filepath.Join(dir, "added.txt"), []byte("hello\n"))
		writeFile(t, filepath.Join(dir, "seed.txt"), []byte("seed\nmore\n"))
	})

	res, err := ApplyProtected(context.Background(), repo, patch)
	if err != nil {
		t.Fatalf("ApplyProtected: %v", err)
	}
	if !res.Applied {
		t.Fatalf("Applied = false: %s", res.Reason)
	}
	if !res.TreeMutated {
		t.Error("TreeMutated = false after a successful apply")
	}
	if len(res.Paths) != 2 {
		t.Errorf("Paths = %v, want both touched files", res.Paths)
	}

	got, err := os.ReadFile(filepath.Join(repo, "added.txt"))
	if err != nil || string(got) != "hello\n" {
		t.Fatalf("added.txt = %q (err %v), want %q", got, err, "hello\n")
	}
}

// Byte fidelity on the live tree: CRLF and binary content must land exactly.
func TestApplyProtectedPreservesCRLFAndBinary(t *testing.T) {
	t.Parallel()
	crlf := []byte("alpha\r\nbeta\r\ngamma\r\n")
	binary := []byte{0x00, 0xff, 0xfe, 0x0d, 0x41, 0x00, 0x90}

	repo := newGitRepo(t)
	base := headSHA(t, repo)
	patch := capturePatch(t, repo, base, func(dir string) {
		writeFile(t, filepath.Join(dir, "crlf.txt"), crlf)
		writeFile(t, filepath.Join(dir, "blob.bin"), binary)
	})

	res, err := ApplyProtected(context.Background(), repo, patch)
	if err != nil {
		t.Fatalf("ApplyProtected: %v", err)
	}
	if !res.Applied {
		t.Fatalf("Applied = false: %s", res.Reason)
	}

	for _, tc := range []struct {
		file string
		want []byte
	}{
		{"crlf.txt", crlf},
		{"blob.bin", binary},
	} {
		got, err := os.ReadFile(filepath.Join(repo, tc.file))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s round-trip mismatch:\n want %q\n  got %q", tc.file, tc.want, got)
		}
	}
}

// The window between capturing the preimage and writing is where a concurrent
// edit does its damage. The apply must refuse — and must NOT undo the other
// party's work while refusing.
func TestApplyProtectedRefusesConcurrentEditWithoutDestroyingIt(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	base := headSHA(t, repo)
	patch := capturePatch(t, repo, base, func(dir string) {
		writeFile(t, filepath.Join(dir, "seed.txt"), []byte("seed\nfrom the agent\n"))
	})

	pre, err := CapturePreimage(context.Background(), repo, patch)
	if err != nil {
		t.Fatalf("CapturePreimage: %v", err)
	}

	// Someone else edits the target in the window.
	concurrent := []byte("seed\nedited by a human meanwhile\n")
	writeFile(t, filepath.Join(repo, "seed.txt"), concurrent)

	res, err := ApplyWithPreimage(context.Background(), repo, patch, pre)
	if err != nil {
		t.Fatalf("ApplyWithPreimage: %v", err)
	}
	if res.Applied {
		t.Fatal("applied a patch against a tree that moved after the preimage was captured")
	}
	if res.TreeMutated {
		t.Error("TreeMutated = true, but the refusal never wrote anything")
	}
	if !strings.Contains(res.Reason, "changed after the preimage was captured") {
		t.Errorf("Reason = %q, want it to name the drift", res.Reason)
	}
	if !strings.Contains(res.Reason, "seed.txt") {
		t.Errorf("Reason = %q, want it to name the drifted path", res.Reason)
	}

	// The refusal must not have rolled the live tree back over the human's work.
	got, err := os.ReadFile(filepath.Join(repo, "seed.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, concurrent) {
		t.Fatalf("the refusal destroyed a concurrent edit:\n want %q\n  got %q", concurrent, got)
	}
}

// A refused FORWARD apply has not touched the tree.
func TestApplyProtectedRefusedForwardApplyLeavesTreeClean(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	base := headSHA(t, repo)
	patch := capturePatch(t, repo, base, func(dir string) {
		writeFile(t, filepath.Join(dir, "seed.txt"), []byte("seed\nagent edit\n"))
	})

	// Make the patch inapplicable by replacing the content it expects.
	diverged := []byte("completely different\n")
	writeFile(t, filepath.Join(repo, "seed.txt"), diverged)
	runGitT(t, repo, "add", "-A")
	runGitT(t, repo, "commit", "-q", "-m", "divergent")

	res, err := ApplyProtected(context.Background(), repo, patch)
	if err != nil {
		t.Fatalf("ApplyProtected: %v", err)
	}
	if res.Applied {
		t.Fatal("a conflicting patch was applied")
	}
	if res.TreeMutated {
		t.Error("TreeMutated = true after a refused forward apply; nothing should have been written")
	}
	if !strings.Contains(res.Reason, "does not apply to the live tree") {
		t.Errorf("Reason = %q", res.Reason)
	}

	got, err := os.ReadFile(filepath.Join(repo, "seed.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, diverged) {
		t.Fatalf("the live tree was modified by a refused apply:\n want %q\n  got %q", diverged, got)
	}
	if status := strings.TrimSpace(runGitT(t, repo, "status", "--porcelain")); status != "" {
		t.Errorf("live tree is dirty after a refused apply:\n%s", status)
	}
}

// The preimage records absence as state: a patch that creates a file assumes
// the file is not already there.
func TestPreimageTreatsAbsenceAsState(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	base := headSHA(t, repo)
	patch := capturePatch(t, repo, base, func(dir string) {
		writeFile(t, filepath.Join(dir, "new.txt"), []byte("created\n"))
	})

	pre, err := CapturePreimage(context.Background(), repo, patch)
	if err != nil {
		t.Fatalf("CapturePreimage: %v", err)
	}
	if got := pre.Entries["new.txt"]; got != absentMarker {
		t.Fatalf("preimage for a not-yet-created file = %q, want %q", got, absentMarker)
	}

	// The file appearing in the window must invalidate the apply.
	writeFile(t, filepath.Join(repo, "new.txt"), []byte("someone got there first\n"))

	res, err := ApplyWithPreimage(context.Background(), repo, patch, pre)
	if err != nil {
		t.Fatalf("ApplyWithPreimage: %v", err)
	}
	if res.Applied {
		t.Fatal("applied over a file that appeared after the preimage was captured")
	}
	if res.TreeMutated {
		t.Error("TreeMutated = true on a refusal")
	}
}

// The preimage digest is order-independent, so two captures of the same state
// compare equal.
func TestPreimageDigestIsStable(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	base := headSHA(t, repo)
	patch := capturePatch(t, repo, base, func(dir string) {
		writeFile(t, filepath.Join(dir, "a.txt"), []byte("a\n"))
		writeFile(t, filepath.Join(dir, "b.txt"), []byte("b\n"))
		writeFile(t, filepath.Join(dir, "seed.txt"), []byte("seed\nx\n"))
	})

	first, err := CapturePreimage(context.Background(), repo, patch)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CapturePreimage(context.Background(), repo, patch)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Fatalf("preimage digest is unstable: %s != %s", first.Digest, second.Digest)
	}
	if first.Digest == "" {
		t.Fatal("preimage digest is empty")
	}
}

// The patch is attacker-influenced input; a path escaping the repository must
// be refused before anything is read or written.
func TestApplyProtectedRejectsPathOutsideRepository(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)

	escape := []byte("diff --git a/../escape.txt b/../escape.txt\n" +
		"new file mode 100644\n" +
		"--- /dev/null\n" +
		"+++ b/../escape.txt\n" +
		"@@ -0,0 +1 @@\n" +
		"+owned\n")

	if _, err := ApplyProtected(context.Background(), repo, escape); err == nil {
		t.Fatal("expected a refusal for a patch referencing a path outside the repository")
	}

	if _, err := os.Stat(filepath.Join(filepath.Dir(repo), "escape.txt")); !os.IsNotExist(err) {
		t.Fatal("a patch escaped the repository root")
	}
}

func TestApplyProtectedEmptyPatchIsANoOp(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)

	res, err := ApplyProtected(context.Background(), repo, nil)
	if err != nil {
		t.Fatalf("ApplyProtected: %v", err)
	}
	if res.Applied || res.TreeMutated {
		t.Errorf("empty patch reported Applied=%v TreeMutated=%v", res.Applied, res.TreeMutated)
	}
	if status := strings.TrimSpace(runGitT(t, repo, "status", "--porcelain")); status != "" {
		t.Errorf("live tree is dirty after an empty patch:\n%s", status)
	}
}
