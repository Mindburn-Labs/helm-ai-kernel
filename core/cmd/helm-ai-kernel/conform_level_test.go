package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// HELM-756: --level L1/L2 ran gates that could not return a truthful result,
// so the levels are retired. The flag still parses and says what to run.
func TestConformLevelsAreRetired(t *testing.T) {
	projectRoot := t.TempDir()
	t.Chdir(projectRoot)
	for _, level := range []string{"L1", "L2"} {
		var stdout, stderr bytes.Buffer
		outputDir := filepath.Join(projectRoot, "artifacts", "conformance-"+level)
		code := runConform([]string{"--level", level, "--output", outputDir, "--signed"}, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("level %s exit=%d, want 2; stderr=%s", level, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "retired in HELM-756") || !strings.Contains(stderr.String(), "conform vectors") {
			t.Fatalf("level %s stderr does not explain the retirement: %s", level, stderr.String())
		}
		if _, err := os.Stat(filepath.Join(outputDir, "conform_report.json")); err == nil {
			t.Fatalf("level %s wrote a conformance report", level)
		}
	}
}

// Only the release gate, G0, still runs; retired profiles and gates fail closed.
func TestConformRejectsRetiredProfilesAndGates(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, args := range [][]string{
		{"--profile", "CORE"},
		{"--profile", "REGULATED_FINANCE"},
		{"--profile", "SMB", "--gate", "G1"},
		{"--profile", "SMB", "--gate", "GX_TENANT"},
	} {
		var stdout, stderr bytes.Buffer
		if code := runConform(args, &stdout, &stderr); code != 2 {
			t.Fatalf("%v exit=%d, want 2; stderr=%s", args, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "HELM-756") {
			t.Fatalf("%v stderr does not name the retirement: %s", args, stderr.String())
		}
	}
}
