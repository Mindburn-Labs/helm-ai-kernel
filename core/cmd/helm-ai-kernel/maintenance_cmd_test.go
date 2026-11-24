package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunMaintenanceReportsPendingWithoutWriting(t *testing.T) {
	chdirTempDir(t)
	if err := os.MkdirAll(incidentsDir(), 0750); err != nil {
		t.Fatal(err)
	}
	fixtures := map[string][]byte{
		"INC-low":    []byte("{\"id\":\"INC-low\",\"title\":\"Low incident\",\"severity\":\"low\",\"status\":\"open\"}\n"),
		"INC-high":   []byte("{\"id\":\"INC-high\",\"title\":\"High incident\",\"severity\":\"high\",\"status\":\"acked\"}\n"),
		"INC-closed": []byte("{\"id\":\"INC-closed\",\"title\":\"Closed incident\",\"severity\":\"critical\",\"status\":\"resolved\"}\n"),
	}
	for id, data := range fixtures {
		if err := os.WriteFile(filepath.Join(incidentsDir(), id+".json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "run", "maintenance", "--max", "1"}, &stdout, &stderr)
	if code != 1 || stdout.String() != "Pending incidents: 2\n  INC-high  high  High incident\n" ||
		!strings.Contains(stderr.String(), "incident show <id>") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for id, want := range fixtures {
		got, err := os.ReadFile(filepath.Join(incidentsDir(), id+".json"))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("incident %s changed: %v", id, err)
		}
	}
	for _, dir := range []string{"maintenance", "events", "receipts"} {
		if _, err := os.Stat(filepath.Join("data", dir)); !os.IsNotExist(err) {
			t.Fatalf("unexpected %s directory: %v", dir, err)
		}
	}
}

func TestRunMaintenanceReportsUnreadableRegistry(t *testing.T) {
	chdirTempDir(t)
	if err := os.MkdirAll(incidentsDir(), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incidentsDir(), "broken.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "run", "maintenance"}, &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "broken.json") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunMaintenanceEmptyRegistryAndInvalidLimit(t *testing.T) {
	chdirTempDir(t)
	var stdout, stderr bytes.Buffer
	command := []string{"helm-ai-kernel", "run", "maintenance"}
	if code := Run(command, &stdout, &stderr); code != 0 || stderr.Len() != 0 ||
		!strings.Contains(stdout.String(), "No open or acknowledged incidents") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := Run(append(command, "--max", "-1"), &stdout, &stderr); code != 2 || stdout.Len() != 0 {
		t.Fatalf("invalid limit: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
