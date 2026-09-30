package main

import (
	"os"
	"path/filepath"
	"testing"
)

// tree builds a root with core/pkg holding the given files.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, src := range files {
		path := filepath.Join(root, "core", "pkg", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestCleanTreePasses(t *testing.T) {
	root := tree(t, map[string]string{"a/a.go": "package a\n\nimport _ \"fmt\"\n"})
	if got := run(root, forbiddenFragments); got != 0 {
		t.Fatalf("clean tree: exit %d, want 0", got)
	}
}

func TestForbiddenImportFails(t *testing.T) {
	root := tree(t, map[string]string{
		"a/a.go": "package a\n\nimport _ \"example.com/ingestion/pipe\"\n",
		// Test files may import anything.
		"a/a_test.go": "package a\n\nimport _ \"example.com/pkg/access\"\n",
	})
	violations, scanned, err := scan(filepath.Join(root, "core", "pkg"), root, forbiddenFragments)
	if err != nil || scanned != 1 || len(violations) != 1 {
		t.Fatalf("violations=%v scanned=%d err=%v; want one violation in one scanned file", violations, scanned, err)
	}
	if got := run(root, forbiddenFragments); got != 1 {
		t.Fatalf("forbidden import: exit %d, want 1", got)
	}
}

func TestParseErrorIsFatal(t *testing.T) {
	// It used to print a warning, skip the file, and pass.
	root := tree(t, map[string]string{
		"a/a.go":      "package a\n",
		"b/broken.go": "package b\n\nimport (\n",
	})
	if got := run(root, forbiddenFragments); got != 2 {
		t.Fatalf("unparseable file: exit %d, want 2", got)
	}
}

func TestEmptyScanIsNotAPass(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "core", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := run(root, forbiddenFragments); got != 2 {
		t.Fatalf("empty core/pkg: exit %d, want 2", got)
	}
	if got := run(t.TempDir(), forbiddenFragments); got != 2 {
		t.Fatalf("missing core/pkg: exit %d, want 2", got)
	}
}

func TestSelfTestRejectsABrokenMatcher(t *testing.T) {
	if got := run(tree(t, map[string]string{"a/a.go": "package a\n"}), nil); got != 2 {
		t.Fatalf("no fragments: exit %d, want 2", got)
	}
	if err := selfTest(forbiddenFragments); err != nil {
		t.Fatalf("self-test on the shipped fragments: %v", err)
	}
}
