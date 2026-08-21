package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/tui"
)

func TestReceiptsExportNDJSONParseable(t *testing.T) {
	dir := t.TempDir()
	receipt := `{
  "receipt_id": "rcpt-ndjson-1",
  "decision_id": "dec-1",
  "status": "DENIED",
  "signature": "ed25519:aabbcc",
  "signature_version": "receipt.v5"
}`
	path := filepath.Join(dir, "rcpt.json")
	if err := os.WriteFile(path, []byte(receipt), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runCLI(t, "receipts", "export", "--ndjson", "--file", path)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if strings.Contains(stdout, "\n  ") {
		t.Fatalf("ndjson must stay compact, got pretty output:\n%s", stdout)
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			lines = append(lines, sc.Text())
		}
	}
	if len(lines) != 1 {
		t.Fatalf("want 1 line, got %d:\n%s", len(lines), stdout)
	}
	var env receiptNDJSONEnvelope
	if err := json.Unmarshal([]byte(lines[0]), &env); err != nil {
		t.Fatalf("line not JSON: %v\n%s", err, lines[0])
	}
	if env.Schema != receiptEnvelopeSchema {
		t.Fatalf("schema=%q", env.Schema)
	}
	var inner map[string]any
	if err := json.Unmarshal(env.Receipt, &inner); err != nil {
		t.Fatalf("receipt unwrap: %v", err)
	}
	if inner["receipt_id"] != "rcpt-ndjson-1" {
		t.Fatalf("receipt_id=%v", inner["receipt_id"])
	}
	if !strings.Contains(env.Verify.Command, "receipts verify") {
		t.Fatalf("verify hint missing: %+v", env.Verify)
	}
	for _, leak := range []string{"HELM_ADMIN_API_KEY", "BEGIN PRIVATE KEY", "Bearer "} {
		if strings.Contains(stdout, leak) {
			t.Fatalf("ndjson leaked %q", leak)
		}
	}
}

func TestReceiptsExportNDJSONDirAndNoSecrets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"receipt_id":"a","signature":"sig-a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"receipt_id":"b","signature":"sig-b"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI(t, "receipts", "export", "--ndjson", "--dir", dir)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	n := 0
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		n++
		if !json.Valid([]byte(sc.Text())) {
			t.Fatalf("invalid ndjson line: %s", sc.Text())
		}
	}
	if n != 2 {
		t.Fatalf("want 2 envelopes, got %d\n%s", n, stdout)
	}
}

func TestReceiptsTailStillListenerRefused(t *testing.T) {
	if !tui.IsListenerVerb("receipts", []string{"tail", "--agent", "x"}) {
		t.Fatal("receipts tail must stay a listener")
	}
	if tui.IsListenerVerb("receipts", []string{"export", "--ndjson", "--file", "r.json"}) {
		t.Fatal("receipts export --ndjson is inspect, not a listener")
	}
}
