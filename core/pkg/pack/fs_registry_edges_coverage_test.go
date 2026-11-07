package pack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writePackManifest(t *testing.T, root, name, version string, manifest PackManifest) {
	t.Helper()

	dir := filepath.Join(root, name, version)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll %s: %v", dir, err)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}
}
