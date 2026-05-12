package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestConformLevelAliasesSeedBaselineEvidence(t *testing.T) {
	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectRoot, "go.sum"), []byte("module lock\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(projectRoot)

	for _, level := range []string{"L1", "L2"} {
		t.Run(level, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			outputDir := filepath.Join(projectRoot, "artifacts", "conformance-"+level)
			code := runConform([]string{"--level", level, "--output", outputDir}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("runConform level %s exit=%d stderr=%s stdout=%s", level, code, stderr.String(), stdout.String())
			}
		})
	}
}
