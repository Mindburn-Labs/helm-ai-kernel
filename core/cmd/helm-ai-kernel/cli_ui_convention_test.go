package main

// Golden tests for the CLI I/O discipline reference slice (W4): these pin the
// unified --format flag surface, the structured error formatter output, and
// the data→stdout / chrome→stderr stream split for the migrated commands.
// See docs/guides/cli-io-convention.md.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// runCLI dispatches one command through the registry with captured streams.
func runCLI(t *testing.T, name string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code, ok := Dispatch(name, args, &stdout, &stderr)
	if !ok {
		t.Fatalf("command %q not registered", name)
	}
	return code, stdout.String(), stderr.String()
}

func assertCleanStdout(t *testing.T, stdout string) {
	t.Helper()
	if stdout != "" {
		t.Fatalf("data stream polluted on error path: %q", stdout)
	}
}

// --- --format flag surface ------------------------------------------------

func TestCLIFormatFlagRiskSummaryJSON(t *testing.T) {
	code, stdout, stderr := runCLI(t, "risk-summary", "--list", "--format=json")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("--format=json stdout not valid JSON: %v\n%s", err, stdout)
	}
	if _, ok := payload["effect_types"]; !ok {
		t.Fatalf("unexpected JSON payload shape: %s", stdout)
	}
}

func TestCLIFormatFlagRejectsUnknownValue(t *testing.T) {
	code, stdout, stderr := runCLI(t, "risk-summary", "--list", "--format", "yaml")
	if code != 2 {
		t.Fatalf("unknown --format accepted: code=%d", code)
	}
	assertCleanStdout(t, stdout)
	if !strings.Contains(stderr, "expected text|json") {
		t.Fatalf("stderr missing format guidance: %q", stderr)
	}
}

func TestCLIFormatFlagMatchesLegacyJSONAlias(t *testing.T) {
	codeA, outA, _ := runCLI(t, "risk-summary", "--list", "--json")
	codeB, outB, _ := runCLI(t, "risk-summary", "--list", "--format=json")
	if codeA != 0 || codeB != 0 {
		t.Fatalf("codes: --json=%d --format=json=%d", codeA, codeB)
	}
	if outA != outB {
		t.Fatalf("--json and --format=json diverged:\n--json: %s\n--format: %s", outA, outB)
	}
}

// --- structured error formatter -------------------------------------------

func TestCLIErrorFormatterGolden(t *testing.T) {
	cases := []struct {
		name     string
		cmd      string
		args     []string
		wantCode int
		wantErr  string // exact first stderr line
	}{
		{"risk-summary missing effect", "risk-summary", nil, 2,
			"Error: risk-summary: --effect or --list is required"},
		{"receipts unknown subcommand", "receipts", []string{"bogus"}, 2,
			"Error: receipts: unknown command: bogus"},
		{"verify decision-receipt missing file", "verify", []string{"decision-receipt"}, 2,
			"Error: verify decision-receipt: provide a receipt file (positional argument or --file)"},
		{"verify entry missing proof", "verify", []string{"--entry", "receipts/x.json"}, 2,
			"Error: verify entry: --proof <file> is required for single-entry verification"},
		{"export aat missing inputs", "export", []string{"aat"}, 2,
			"Error: export aat: --in and --agent-id are required (or use --verify)"},
		{"log unknown subcommand", "log", []string{"bogus"}, 2,
			"Error: log: unknown subcommand: bogus"},
		{"log append missing leaf hash", "log", []string{"append"}, 2,
			"Error: log append: --leaf-hash is required"},
		{"plan unknown subcommand", "plan", []string{"bogus"}, 2,
			"Error: plan: unknown subcommand: bogus"},
		{"plan evaluate missing plan", "plan", []string{"evaluate", "--dry-run"}, 2,
			"Error: plan evaluate: --plan is required"},
		{"trust unknown subcommand", "trust", []string{"bogus"}, 2,
			"Error: trust: unknown subcommand: bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, tc.cmd, tc.args...)
			if code != tc.wantCode {
				t.Fatalf("code=%d want %d (stderr=%s)", code, tc.wantCode, stderr)
			}
			assertCleanStdout(t, stdout)
			firstLine, _, _ := strings.Cut(stderr, "\n")
			if firstLine != tc.wantErr {
				t.Fatalf("error line drifted:\n got: %q\nwant: %q", firstLine, tc.wantErr)
			}
			if strings.Contains(stderr, "goroutine ") || strings.Contains(stderr, "panic:") {
				t.Fatalf("stack noise leaked into user error: %q", stderr)
			}
		})
	}
}

// --- remediation hints ----------------------------------------------------

func TestCLIErrorHintGolden(t *testing.T) {
	_, _, stderr := runCLI(t, "log", "bogus")
	if !strings.Contains(stderr, "\n  hint: append|sth|prove|verify-inclusion|verify-consistency") {
		t.Fatalf("hint line missing or drifted: %q", stderr)
	}
}

// --- data/chrome split on success paths -----------------------------------

func TestCLIVerifyEntryFormatFlagJSON(t *testing.T) {
	// Missing proof file must fail before any data emission.
	code, stdout, stderr := runCLI(t, "verify", "--entry", "receipts/x.json", "--proof", "/nonexistent/proof.json", "--format=json")
	if code != 2 {
		t.Fatalf("code=%d", code)
	}
	assertCleanStdout(t, stdout)
	if !strings.HasPrefix(stderr, "Error: verify entry: cannot read proof: ") {
		t.Fatalf("wrapped error drifted: %q", stderr)
	}
}
