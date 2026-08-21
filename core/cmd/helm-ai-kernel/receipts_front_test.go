package main

import (
	"strings"
	"testing"
)

func TestReceiptsCanonicalVerbs(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "receipts", "bogus")
		if code != 2 {
			t.Fatalf("code=%d", code)
		}
		assertCleanStdout(t, stdout)
		if !strings.Contains(stderr, "unknown command") {
			t.Fatalf("stderr=%q", stderr)
		}
	})
	t.Run("list is not SSE", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "receipts", "list", "--format=json")
		if code > 2 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		out := stdout + stderr
		if strings.Contains(out, "text/event-stream") || strings.Contains(out, "event-stream") {
			t.Fatalf("list started a tail:\n%s", out)
		}
		if !strings.Contains(stdout, `"status"`) && !strings.Contains(stdout, "FAIL") {
			t.Fatalf("list produced no inspect document:\n%s", stdout)
		}
	})
	t.Run("show requires an id", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "receipts", "show")
		if code != 2 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		assertCleanStdout(t, stdout)
		if !strings.Contains(stderr, "receipt id") && !strings.Contains(stderr, "--id") {
			t.Fatalf("stderr=%q", stderr)
		}
	})
	t.Run("verify aliases verify receipt", func(t *testing.T) {
		code, _, stderr := runCLI(t, "receipts", "verify")
		if code != 2 {
			t.Fatalf("code=%d", code)
		}
		if !strings.Contains(stderr, "verify receipt") && !strings.Contains(stderr, "--receipt") {
			t.Fatalf("verify alias did not reach verify receipt: %q", stderr)
		}
	})
	t.Run("export aliases export", func(t *testing.T) {
		code, _, stderr := runCLI(t, "receipts", "export")
		if code != 2 {
			t.Fatalf("code=%d", code)
		}
		if !strings.Contains(stderr, "--evidence") && !strings.Contains(stderr, "export") {
			t.Fatalf("export alias did not reach export: %q", stderr)
		}
	})
	t.Run("help names the front", func(t *testing.T) {
		var stdout, stderr strings.Builder
		code, ok := Dispatch("receipts", []string{"--help"}, &stdout, &stderr)
		if !ok || code != 0 {
			t.Fatalf("help code=%d ok=%v stderr=%s", code, ok, stderr.String())
		}
		body := stdout.String()
		for _, verb := range []string{"status", "list", "show", "tail", "verify", "export"} {
			if !strings.Contains(body, verb) {
				t.Fatalf("receipts help missing %q:\n%s", verb, body)
			}
		}
	})
}
