package main

import (
	"bytes"
	"encoding/json"
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
			code := runConform([]string{"--level", level, "--output", outputDir, "--signed"}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("runConform level %s exit=%d stderr=%s stdout=%s", level, code, stderr.String(), stdout.String())
			}
			reportPath := filepath.Join(outputDir, "conform_report.json")
			if _, err := os.Stat(reportPath); err == nil {
				data, err := os.ReadFile(reportPath)
				if err != nil {
					t.Fatalf("read report: %v", err)
				}
				var report struct {
					Metadata map[string]any `json:"metadata"`
				}
				if err := json.Unmarshal(data, &report); err != nil {
					t.Fatalf("decode report: %v", err)
				}
				if report.Metadata["evidence_mode"] != "seeded-local-baseline" {
					t.Fatalf("level alias report evidence_mode = %v, want seeded-local-baseline", report.Metadata["evidence_mode"])
				}
			}
		})
	}
}
