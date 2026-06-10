package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

func writeAATTestEntries(t *testing.T, dir string) string {
	t.Helper()
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	entries := []*store.AuditEntry{
		{
			EntryID:     "00000000-0000-0000-0000-000000000001",
			Sequence:    1,
			Timestamp:   base,
			EntryType:   store.EntryTypeAudit,
			Subject:     "tenant:acme",
			Action:      "tool.call",
			PayloadHash: "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11",
		},
		{
			EntryID:     "00000000-0000-0000-0000-000000000002",
			Sequence:    2,
			Timestamp:   base.Add(time.Second),
			EntryType:   store.EntryTypeAudit,
			Subject:     "tenant:acme",
			Action:      "verdict.allow",
			PayloadHash: "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22",
		},
	}
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal entries: %v", err)
	}
	path := filepath.Join(dir, "entries.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write entries: %v", err)
	}
	return path
}

func TestExportAATRoundTrip(t *testing.T) {
	dir := t.TempDir()
	inPath := writeAATTestEntries(t, dir)
	outPath := filepath.Join(dir, "out.jsonl")

	var stdout, stderr bytes.Buffer
	signKey := strings.Repeat("42", 32)
	code := runExportCmd([]string{"aat", "--in", inPath, "--out", outPath, "--agent-id", "agent-1", "--sign-key", signKey}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("export aat exited %d: %s", code, stderr.String())
	}
	first, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if len(bytes.Split(bytes.TrimSpace(first), []byte("\n"))) != 2 {
		t.Fatalf("expected 2 AAT records, got: %s", first)
	}

	// Deterministic: re-export must be byte-identical.
	outPath2 := filepath.Join(dir, "out2.jsonl")
	stdout.Reset()
	stderr.Reset()
	if code := runExportCmd([]string{"aat", "--in", inPath, "--out", outPath2, "--agent-id", "agent-1", "--sign-key", signKey}, &stdout, &stderr); code != 0 {
		t.Fatalf("second export exited %d: %s", code, stderr.String())
	}
	second, err := os.ReadFile(outPath2)
	if err != nil {
		t.Fatalf("read second output: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("AAT CLI export is not deterministic")
	}

	// Verify mode passes on a valid chain.
	stdout.Reset()
	stderr.Reset()
	if code := runExportCmd([]string{"aat", "--verify", outPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("verify exited %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "AAT chain OK") {
		t.Fatalf("unexpected verify output: %s", stdout.String())
	}

	// Verify mode fails closed on tampered content.
	tampered := bytes.Replace(first, []byte("tool.call"), []byte("tool.exec"), 1)
	tamperedPath := filepath.Join(dir, "tampered.jsonl")
	if err := os.WriteFile(tamperedPath, tampered, 0600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runExportCmd([]string{"aat", "--verify", tamperedPath}, &stdout, &stderr); code != 1 {
		t.Fatalf("expected exit 1 for tampered chain, got %d: %s", code, stderr.String())
	}
}

func TestExportAATUsageErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runExportCmd([]string{"aat"}, &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2 without --in/--agent-id, got %d", code)
	}
	if code := runExportCmd([]string{"aat", "--in", "x.json", "--agent-id", "a", "--sign-key", "zz"}, &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2 for malformed sign key, got %d", code)
	}
}
