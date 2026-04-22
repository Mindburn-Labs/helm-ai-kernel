package contracts_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEvidencePackSingleSource ensures there is exactly one EvidencePack struct definition in the repo.
func TestEvidencePackSingleSource(t *testing.T) {
	wd, _ := os.Getwd()
	root := filepath.Join(wd, "../../../")

	skipDirs := map[string]struct{}{
		".git":         {},
		"node_modules": {},
		"dist":         {},
		"artifacts":    {},
		"vendor":       {},
	}

	needle := []byte("type EvidencePack struct")
	count := 0

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if _, ok := skipDirs[d.Name()]; ok {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		if filepath.Ext(path) == ".go" && strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		count += bytes.Count(data, needle)
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}

	if count != 1 {
		t.Fatalf("expected exactly 1 EvidencePack struct definition, found %d", count)
	}
}
