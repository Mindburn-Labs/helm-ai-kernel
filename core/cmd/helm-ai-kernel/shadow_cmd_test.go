package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A path the scanner cannot read has no grade: not from `shadow scan`, and not
// from `autoconfigure` or `setup`, which reuse its scan and would otherwise
// record an A for a workspace nobody read.
func TestShadowScanMissingPathIsAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	for _, args := range [][]string{{"--path", missing}, {"--path", missing, "--json"}} {
		var stdout, stderr bytes.Buffer
		code := runShadowScan(args, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "nothing could be examined") {
			t.Fatalf("shadow scan %v: exit = %d, stderr = %q, want exit 2 and the reason", args, code, stderr.String())
		}
		if strings.Contains(stdout.String(), "grade") {
			t.Fatalf("shadow scan %v graded a path it could not read: %s", args, stdout.String())
		}
	}

	outDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := runAutoconfigureScan([]string{"--path", missing, "--out", outDir}, &stdout, &stderr); code != 2 {
		t.Fatalf("autoconfigure scan: exit = %d, want 2; stdout = %s", code, stdout.String())
	}
	if _, err := os.Stat(filepath.Join(outDir, "inventory.json")); !os.IsNotExist(err) {
		t.Fatalf("autoconfigure scan wrote an inventory for a path it could not read: %v", err)
	}

	if grade, _, err := runSetupAutoconfigure(t.TempDir(), missing); err == nil {
		t.Fatalf("setup autoconfigure graded a missing workspace %q", grade)
	}
}

// --require-complete is for callers that need a grade over the whole tree: any
// in-scope path the scanner could not read in full fails the scan instead of
// being skipped and counted.
func TestShadowScanRequireCompleteRefusesPartialCoverage(t *testing.T) {
	readable := t.TempDir()
	if err := os.WriteFile(filepath.Join(readable, "readable.py"), []byte("print('no agent here')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runShadowScan([]string{"--path", readable, "--require-complete"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "Boundary grade") {
		t.Fatalf("complete scan: exit = %d, stderr = %q, stdout = %s", code, stderr.String(), stdout.String())
	}

	// A candidate over the size limit is skipped by the default scan and is a
	// coverage gap for a complete one.
	oversized := t.TempDir()
	if err := os.WriteFile(filepath.Join(oversized, "readable.py"), []byte("print('no agent here')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oversized, "bundle.js"), bytes.Repeat([]byte("x\n"), 1024*1024+1), 0o644); err != nil {
		t.Fatal(err)
	}
	partial := map[string]string{"oversized candidate": oversized}

	if os.Geteuid() != 0 {
		locked := t.TempDir()
		if err := os.WriteFile(filepath.Join(locked, "readable.py"), []byte("print('no agent here')\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		lockedDir := filepath.Join(locked, "locked")
		if err := os.Mkdir(lockedDir, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(lockedDir, 0o755) })
		partial["unreadable directory"] = locked
	}

	for name, root := range partial {
		stdout.Reset()
		stderr.Reset()
		if code := runShadowScan([]string{"--path", root}, &stdout, &stderr); code != 0 {
			t.Fatalf("%s: default scan exit = %d, stderr = %q", name, code, stderr.String())
		}
		for _, args := range [][]string{{"--path", root, "--require-complete"}, {"--path", root, "--require-complete", "--json"}} {
			stdout.Reset()
			stderr.Reset()
			code := runShadowScan(args, &stdout, &stderr)
			if code != 2 || !strings.Contains(stderr.String(), "scan coverage incomplete") || stdout.Len() != 0 {
				t.Fatalf("%s %v: exit = %d, stderr = %q, stdout = %q, want exit 2, the reason and no report", name, args, code, stderr.String(), stdout.String())
			}
		}
	}
}

// Entries the scanner could not read are shown apart from the files it read,
// in the text report, the JSON report and the grade reason.
func TestShadowScanShowsUnreadablePaths(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not restrict root")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "readable.py"), []byte("print('no agent here')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "agent.py"), []byte("import openai\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	var text, stderr bytes.Buffer
	if code := runShadowScan([]string{"--path", root}, &text, &stderr); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	for _, want := range []string{"Unreadable:    1 path(s) skipped", "1 path(s) could not be read"} {
		if !strings.Contains(text.String(), want) {
			t.Fatalf("text report does not show %q:\n%s", want, text.String())
		}
	}

	var jsonOut bytes.Buffer
	if code := runShadowScan([]string{"--path", root, "--json"}, &jsonOut, &stderr); code != 0 {
		t.Fatalf("json exit = %d, stderr = %s", code, stderr.String())
	}
	var report struct {
		FilesScanned    int `json:"files_scanned"`
		PathsUnreadable int `json:"paths_unreadable"`
		Grade           struct {
			Reason string `json:"reason"`
		} `json:"grade"`
	}
	if err := json.Unmarshal(jsonOut.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, jsonOut.String())
	}
	if report.FilesScanned != 1 || report.PathsUnreadable != 1 || !strings.Contains(report.Grade.Reason, "1 path(s) could not be read") {
		t.Fatalf("json report = %+v", report)
	}
}
