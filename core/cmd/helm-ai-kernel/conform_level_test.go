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
			if code != 1 {
				t.Fatalf("runConform level %s exit=%d stderr=%s stdout=%s, want fail-closed exit 1", level, code, stderr.String(), stdout.String())
			}
			reportPath := filepath.Join(outputDir, "conform_report.json")
			if _, err := os.Stat(reportPath); err == nil {
				data, err := os.ReadFile(reportPath)
				if err != nil {
					t.Fatalf("read report: %v", err)
				}
				var report struct {
					Metadata    map[string]any `json:"metadata"`
					GateResults []struct {
						GateID  string   `json:"gate_id"`
						Pass    bool     `json:"pass"`
						Reasons []string `json:"reasons"`
					} `json:"gate_results"`
				}
				if err := json.Unmarshal(data, &report); err != nil {
					t.Fatalf("decode report: %v", err)
				}
				if report.Metadata["evidence_mode"] != "seeded-local-baseline" {
					t.Fatalf("level alias report evidence_mode = %v, want seeded-local-baseline", report.Metadata["evidence_mode"])
				}
				foundG1 := false
				for _, gate := range report.GateResults {
					if gate.GateID != "G1" {
						continue
					}
					foundG1 = true
					if gate.Pass {
						t.Fatalf("G1 unexpectedly passed without signed receipts")
					}
					if !stringSliceContains(gate.Reasons, "SIGNATURE_INVALID") {
						t.Fatalf("G1 reasons = %v, want SIGNATURE_INVALID", gate.Reasons)
					}
				}
				if !foundG1 {
					t.Fatalf("report did not include G1 result")
				}
			}
		})
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
