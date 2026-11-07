package pack_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// repoRoot returns the root of the helm-ai-kernel repository by walking up
// from this test file's location (core/pkg/pack/).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
}

// TestReferencePacks_Parseable verifies that the reference_packs at the repo
// root are valid JSON and contain expected top-level fields.
func TestReferencePacks_Parseable(t *testing.T) {
	root := repoRoot(t)
	packsDir := filepath.Join(root, "reference_packs")
	if _, err := os.Stat(packsDir); err != nil {
		t.Skipf("reference_packs directory not found at %s: %v", packsDir, err)
	}

	entries, err := os.ReadDir(packsDir)
	if err != nil {
		t.Fatalf("cannot read reference_packs: %v", err)
	}

	packCount := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		packCount++

		t.Run(entry.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(packsDir, entry.Name()))
			if err != nil {
				t.Fatalf("cannot read %s: %v", entry.Name(), err)
			}

			var raw map[string]interface{}
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatalf("%s is not valid JSON: %v", entry.Name(), err)
			}

			// Every reference pack must have pack_id and label.
			if _, ok := raw["pack_id"]; !ok {
				t.Errorf("%s missing pack_id field", entry.Name())
			}
			if _, ok := raw["label"]; !ok {
				t.Errorf("%s missing label field", entry.Name())
			}
		})
	}

	if packCount == 0 {
		t.Error("no reference pack JSON files found in reference_packs/")
	}
}
