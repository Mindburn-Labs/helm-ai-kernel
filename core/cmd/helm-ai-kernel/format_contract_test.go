package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestCatalogCommandsRejectUnknownFormat(t *testing.T) {
	for _, cmd := range commandCatalog().Commands {
		if cmd.Format == "collision" {
			continue
		}
		t.Run(cmd.Name, func(t *testing.T) {
			code, stdout, stderr := invokeCatalog(t, cmd.Name, "--format=yaml")
			if stdout != "" && looksLikeStartedListener(stdout) {
				t.Fatalf("unknown --format started work:\n%s", stdout)
			}
			if code != 2 {
				t.Fatalf("code=%d want 2 stderr=%s", code, stderr)
			}
			if !strings.Contains(stderr, "expected text|json") {
				t.Fatalf("stderr missing format contract: %q", stderr)
			}
		})
	}
}

func TestCatalogFormatFieldDocumentsExemptions(t *testing.T) {
	for _, cmd := range commandCatalog().Commands {
		switch cmd.Format {
		case "text|json", "exempt", "collision":
		default:
			t.Fatalf("%s format=%q is not a documented contract", cmd.Name, cmd.Format)
		}
		if reason, ok := operatorFormatCollision[cmd.Name]; ok && cmd.Format != "collision" {
			t.Fatalf("%s should be collision (%s)", cmd.Name, reason)
		}
		if reason, ok := operatorFormatDocumentExempt[cmd.Name]; ok && cmd.Format != "exempt" {
			t.Fatalf("%s should be exempt (%s)", cmd.Name, reason)
		}
	}
}

func TestCatalogFormatJSONRewritesOrPassthrough(t *testing.T) {
	for _, cmd := range commandCatalog().Commands {
		if cmd.Format == "collision" {
			continue
		}
		t.Run(cmd.Name, func(t *testing.T) {
			rest, code, ok := applyOperatorFormat(cmd.Name, []string{"--format=json"}, io.Discard)
			if !ok || code != 0 {
				t.Fatalf("applyOperatorFormat code=%d ok=%v", code, ok)
			}
			joined := strings.Join(rest, " ")
			if _, passthrough := operatorFormatPassthrough[cmd.Name]; passthrough {
				if !strings.Contains(joined, "format") {
					t.Fatalf("passthrough dropped --format: %q", joined)
				}
				return
			}
			if strings.Contains(joined, "--format") {
				t.Fatalf("rewrite left --format in argv: %q", joined)
			}
			if !strings.Contains(joined, "--json") {
				t.Fatalf("rewrite missing --json alias: %q", joined)
			}
		})
	}
}

func TestRepresentativeCommandsEmitJSON(t *testing.T) {
	cases := []struct {
		name string
		args []string
		key  string
	}{
		{"doctor", []string{"--format=json"}, "checks"},
		{"help", []string{"--format=json"}, "schema_version"},
		{"version", []string{"--format=json"}, "version"},
		{"receipts", []string{"status", "--format=json"}, "server"},
		{"risk-summary", []string{"--list", "--format=json"}, "effect_types"},
		{"freeze", []string{"--status", "--format=json"}, "frozen"},
		{"health", []string{"--format=json"}, "status"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := invokeCatalog(t, tc.name, tc.args...)
			if code > 2 {
				t.Fatalf("code=%d stderr=%s", code, stderr)
			}
			var payload map[string]any
			if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
				t.Fatalf("stdout not JSON: %v\n%s\nstderr=%s", err, stdout, stderr)
			}
			if _, ok := payload[tc.key]; !ok {
				t.Fatalf("missing %q in %s", tc.key, stdout)
			}
		})
	}
}

func TestLeadingOperatorFormatBeforeSubcommand(t *testing.T) {
	t.Run("budget --format=json list", func(t *testing.T) {
		code, stdout, stderr := invokeCatalog(t, "budget", "--format=json", "list")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		var budgets []map[string]any
		if err := json.Unmarshal([]byte(stdout), &budgets); err != nil {
			t.Fatalf("stdout not JSON array: %v\n%s", err, stdout)
		}
		if len(budgets) == 0 {
			t.Fatal("expected bootstrap budget")
		}
	})
	t.Run("budget list --format json still works", func(t *testing.T) {
		code, stdout, stderr := invokeCatalog(t, "budget", "list", "--format", "json")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		var budgets []map[string]any
		if err := json.Unmarshal([]byte(stdout), &budgets); err != nil {
			t.Fatalf("stdout not JSON array: %v\n%s", err, stdout)
		}
	})
	t.Run("receipts --format=json status", func(t *testing.T) {
		code, stdout, stderr := invokeCatalog(t, "receipts", "--format=json", "status")
		if code > 2 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
			t.Fatalf("stdout not JSON: %v\n%s\nstderr=%s", err, stdout, stderr)
		}
		if _, ok := payload["server"]; !ok {
			t.Fatalf("missing server in %s", stdout)
		}
	})
	t.Run("receipts status --format=json still works", func(t *testing.T) {
		code, stdout, stderr := invokeCatalog(t, "receipts", "status", "--format=json")
		if code > 2 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
			t.Fatalf("stdout not JSON: %v\n%s", err, stdout)
		}
	})
	t.Run("relocateLeadingOperatorFormat", func(t *testing.T) {
		got := strings.Join(relocateLeadingOperatorFormat([]string{"--format=json", "status"}), " ")
		if got != "status --format=json" {
			t.Fatalf("got %q", got)
		}
		got = strings.Join(relocateLeadingOperatorFormat([]string{"--format", "json", "list", "--limit", "4"}), " ")
		if got != "list --format json --limit 4" {
			t.Fatalf("got %q", got)
		}
		got = strings.Join(relocateLeadingOperatorFormat([]string{"list", "--format=json"}), " ")
		if got != "list --format=json" {
			t.Fatalf("got %q", got)
		}
		// Flag-only argv must not reshuffle value positions.
		got = strings.Join(relocateLeadingOperatorFormat([]string{"--format=json", "--effect", "--format=text", "--bogus"}), " ")
		if got != "--format=json --effect --format=text --bogus" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestEvidenceScopesListEmptyIsHonest(t *testing.T) {
	t.Setenv("HELM_DATA_DIR", t.TempDir())
	t.Run("text empty emits chrome count", func(t *testing.T) {
		code, stdout, stderr := invokeCatalog(t, "evidence", "scopes", "list")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if strings.TrimSpace(stdout) != "" {
			t.Fatalf("text empty must keep stdout empty, got %q", stdout)
		}
		if !strings.Contains(stderr, "evidence scopes: 0") {
			t.Fatalf("text empty missing chrome count: %q", stderr)
		}
	})
	t.Run("json empty emits []", func(t *testing.T) {
		code, stdout, stderr := invokeCatalog(t, "evidence", "scopes", "list", "--format=json")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		var items []any
		if err := json.Unmarshal([]byte(stdout), &items); err != nil {
			t.Fatalf("stdout not JSON array: %v\n%s\nstderr=%s", err, stdout, stderr)
		}
		if len(items) != 0 {
			t.Fatalf("want [], got %s", stdout)
		}
	})
	t.Run("json alias empty emits []", func(t *testing.T) {
		code, stdout, stderr := invokeCatalog(t, "evidence", "scopes", "list", "--json")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		var items []any
		if err := json.Unmarshal([]byte(stdout), &items); err != nil {
			t.Fatalf("stdout not JSON array: %v\n%s", err, stdout)
		}
	})
}

func invokeCatalog(t *testing.T, name string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code, ok := Dispatch(name, args, &stdout, &stderr)
	if !ok {
		code = Run(append([]string{"helm-ai-kernel", name}, args...), &stdout, &stderr)
	}
	return code, stdout.String(), stderr.String()
}

func looksLikeStartedListener(stdout string) bool {
	body := strings.ToLower(stdout)
	return strings.Contains(body, "listening") || strings.Contains(body, "started server")
}
