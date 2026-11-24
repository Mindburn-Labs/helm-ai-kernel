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
		{"verify receipt missing flags", "verify", []string{"receipt"}, 2,
			"Error: verify receipt: --receipt and --trusted-public-key-file are required"},
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
	// Missing proof file must fail before any data emission; under
	// --format=json the error is the structured envelope on stderr.
	code, stdout, stderr := runCLI(t, "verify", "--entry", "receipts/x.json", "--proof", "/nonexistent/proof.json", "--format=json")
	if code != 2 {
		t.Fatalf("code=%d", code)
	}
	assertCleanStdout(t, stdout)
	if !strings.HasPrefix(stderr, `{"error":{"op":"verify entry","message":"cannot read proof: `) {
		t.Fatalf("wrapped error drifted: %q", stderr)
	}
}

// --- Golden: JSON error envelope under --format=json (permit advisory P3) --

func TestCLIJSONErrorEnvelopeWired(t *testing.T) {
	code, stdout, stderr := runCLI(t, "risk-summary", "--format=json")
	if code != 2 {
		t.Fatalf("code=%d want 2", code)
	}
	assertCleanStdout(t, stdout)
	want := `{"error":{"op":"risk-summary","message":"--effect or --list is required","code":2}}`
	firstLine, _, _ := strings.Cut(stderr, "\n")
	if firstLine != want {
		t.Fatalf("envelope drifted:\n got: %q\nwant: %q", firstLine, want)
	}

	// Text mode (no --format) keeps the human form.
	_, _, stderr = runCLI(t, "risk-summary")
	firstLine, _, _ = strings.Cut(stderr, "\n")
	if firstLine != "Error: risk-summary: --effect or --list is required" {
		t.Fatalf("text form drifted: %q", firstLine)
	}

	// verify entry emits the envelope for operational errors too.
	code, stdout, stderr = runCLI(t, "verify", "--entry", "receipts/x.json", "--proof", "/nonexistent/proof.json", "--format=json")
	if code != 2 {
		t.Fatalf("code=%d want 2", code)
	}
	assertCleanStdout(t, stdout)
	if !strings.HasPrefix(stderr, `{"error":{"op":"verify entry","message":"cannot read proof: `) {
		t.Fatalf("verify entry envelope drifted: %q", stderr)
	}
}

// --- Regression: permit round-3 P2s ----------------------------------------

// assertSingleJSONDocument fails unless s is exactly one JSON value.
func assertSingleJSONDocument(t *testing.T, s string) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("stderr not JSON: %v\n%s", err, s)
	}
	if dec.More() {
		t.Fatalf("trailing content after JSON document: %q", s)
	}
	if _, ok := doc["error"]; !ok {
		t.Fatalf("expected error envelope, got: %s", s)
	}
}

func TestCLILegacyJSONAliasSelectsErrorEnvelope(t *testing.T) {
	// P2 LEGACY_JSON_ERROR_FORMAT_DIVERGENCE: --json must select the JSON
	// error envelope, not just JSON success output.
	code, stdout, stderr := runCLI(t, "risk-summary", "--json")
	if code != 2 {
		t.Fatalf("code=%d want 2", code)
	}
	assertCleanStdout(t, stdout)
	assertSingleJSONDocument(t, strings.TrimSpace(stderr)+"\n")
}

func TestCLIJSONModeStderrIsOneDocument(t *testing.T) {
	// P2 JSON_ERROR_STREAM_NOT_PARSEABLE: no plain usage text may follow the
	// envelope in JSON mode.
	cases := []struct {
		name string
		cmd  string
		args []string
	}{
		{"risk-summary format=json", "risk-summary", []string{"--format=json"}},
		{"risk-summary legacy --json", "risk-summary", []string{"--json"}},
		{"verify entry missing proof", "verify", []string{"--entry", "r/x.json", "--format=json"}},
		{"verify entry legacy --json", "verify", []string{"--entry", "r/x.json", "--json"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, tc.cmd, tc.args...)
			if code != 2 {
				t.Fatalf("code=%d want 2 (stderr=%s)", code, stderr)
			}
			assertCleanStdout(t, stdout)
			assertSingleJSONDocument(t, stderr)
		})
	}
}

func TestCLITextModeKeepsHumanErrorForm(t *testing.T) {
	// risk-summary text mode keeps the human error + usage lines.
	_, _, stderr := runCLI(t, "risk-summary")
	if !strings.HasPrefix(stderr, "Error: risk-summary: --effect or --list is required\n") {
		t.Fatalf("text error drifted: %q", stderr)
	}
	if !strings.Contains(stderr, "Usage: helm-ai-kernel risk-summary --effect INFRA_DESTROY") {
		t.Fatalf("usage lines missing in text mode: %q", stderr)
	}
}

// --- Regression: decision-receipt JSON-mode errors (permit round-4 P2) -----

func TestCLIDecisionReceiptJSONErrorEnvelope(t *testing.T) {
	// P2 DECISION_RECEIPT_JSON_ERRORS_TEXT: --json selects the envelope even
	// though --format is the receipt-format-id collision exception.
	code, stdout, stderr := runCLI(t, "verify", "decision-receipt", "--json")
	if code != 2 {
		t.Fatalf("code=%d want 2", code)
	}
	assertCleanStdout(t, stdout)
	assertSingleJSONDocument(t, stderr)

	// Read failure under --json is also a single envelope document.
	code, stdout, stderr = runCLI(t, "verify", "decision-receipt", "--json", "/nonexistent/receipt.json")
	if code != 2 {
		t.Fatalf("code=%d want 2", code)
	}
	assertCleanStdout(t, stdout)
	assertSingleJSONDocument(t, stderr)

	// Text mode keeps the human form.
	_, _, stderr = runCLI(t, "verify", "decision-receipt")
	if !strings.HasPrefix(stderr, "Error: verify decision-receipt: provide a receipt file") {
		t.Fatalf("text form drifted: %q", stderr)
	}
}

// --- Regression: JSON-mode flag parse errors (permit round-5 P2) -----------

func TestCLIJSONModeFlagParseErrorIsEnvelope(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		args []string
	}{
		{"risk-summary format then bad flag", "risk-summary", []string{"--format=json", "--bogus"}},
		{"risk-summary bad flag then format", "risk-summary", []string{"--bogus", "--format=json"}},
		{"risk-summary legacy json", "risk-summary", []string{"--json", "--bogus"}},
		{"verify entry", "verify", []string{"--entry", "r/x.json", "--json", "--bogus"}},
		{"receipts tail", "receipts", []string{"tail", "--agent", "a1", "--format=json", "--bogus"}},
		{"trust eu-list status", "trust", []string{"eu-list", "status", "--json", "--bogus"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, tc.cmd, tc.args...)
			if code != 2 {
				t.Fatalf("code=%d want 2 (stderr=%s)", code, stderr)
			}
			assertCleanStdout(t, stdout)
			assertSingleJSONDocument(t, stderr)
		})
	}
}

func TestCLITextModeFlagParseErrorClean(t *testing.T) {
	code, _, stderr := runCLI(t, "risk-summary", "--bogus")
	if code != 2 {
		t.Fatalf("code=%d want 2", code)
	}
	if stderr != "Error: risk-summary: flag provided but not defined: -bogus\n" {
		t.Fatalf("text parse error drifted: %q", stderr)
	}
}

// --- Regression: value-position tokens never select the mode (round-7 P2) --

func TestCLIValuePositionTokenNeverSelectsFormat(t *testing.T) {
	// Reviewer's exact example: the second --format token is consumed as the
	// --effect value, so JSON (from the first --format=json) wins and the
	// parse failure renders as one envelope document.
	code, stdout, stderr := runCLI(t, "risk-summary", "--format=json", "--effect", "--format=text", "--bogus")
	if code != 2 {
		t.Fatalf("code=%d want 2 (stderr=%s)", code, stderr)
	}
	assertCleanStdout(t, stdout)
	assertSingleJSONDocument(t, stderr)

	// Symmetric: a selector swallowed as a value must NOT flip to JSON.
	code, _, stderr = runCLI(t, "risk-summary", "--effect", "--json", "--bogus")
	if code != 2 {
		t.Fatalf("code=%d want 2", code)
	}
	if !strings.HasPrefix(stderr, "Error: risk-summary: flag provided but not defined") {
		t.Fatalf("expected text parse error, got %q", stderr)
	}
}

// --- Regression: command-aware scan end to end (round-8 P2) -----------------

func TestCLIUnknownValueFlagNameDoesNotConsumeSelector(t *testing.T) {
	// P2 FORMAT_SCAN_NOT_COMMAND_AWARE: --agent is not a risk-summary flag,
	// so the flag package stops there and the trailing --format=json still
	// selects the envelope for the parse error.
	code, stdout, stderr := runCLI(t, "risk-summary", "--agent", "--format=json")
	if code != 2 {
		t.Fatalf("code=%d want 2 (stderr=%s)", code, stderr)
	}
	assertCleanStdout(t, stdout)
	assertSingleJSONDocument(t, stderr)

	// On receipts tail, --agent IS a value flag: it consumes --format=json,
	// so the (earlier) unknown-flag error renders in the text default.
	code, _, stderr = runCLI(t, "receipts", "tail", "--bogus2", "--agent", "--format=json")
	if code != 2 {
		t.Fatalf("code=%d want 2", code)
	}
	if !strings.HasPrefix(stderr, "Error: receipts tail: flag provided but not defined") {
		t.Fatalf("expected text parse error, got %q", stderr)
	}
}

// --- Regression: round-9 P2s ------------------------------------------------

func TestCLIDecisionReceiptFormatIDNotSelector(t *testing.T) {
	// P2 FORMAT_COLLISION_PARSE_ERROR_MODE: on verify decision-receipt,
	// --format is a receipt id; --json is the only output selector.
	code, stdout, stderr := runCLI(t, "verify", "decision-receipt", "--json", "--format", "text", "--bogus")
	if code != 2 {
		t.Fatalf("code=%d want 2 (stderr=%s)", code, stderr)
	}
	assertCleanStdout(t, stdout)
	assertSingleJSONDocument(t, stderr)
}

// --- Regression: conflicting aliases render the effective mode (round-11 P2)

func TestCLIConflictingAliasesUseEffectiveMode(t *testing.T) {
	// P2 CONFLICTING_FORMAT_FLAGS_DIVERGE: --format=json --json=false parses
	// into JSON mode (OR semantics), so the parse failure is the envelope.
	code, stdout, stderr := runCLI(t, "risk-summary", "--format=json", "--json=false", "--bogus")
	if code != 2 {
		t.Fatalf("code=%d want 2 (stderr=%s)", code, stderr)
	}
	assertCleanStdout(t, stdout)
	assertSingleJSONDocument(t, stderr)

	// And the post-parse path agrees: same flags, valid parse → JSON error.
	code, stdout, stderr = runCLI(t, "risk-summary", "--format=json", "--json=false")
	if code != 2 {
		t.Fatalf("code=%d want 2 (stderr=%s)", code, stderr)
	}
	assertCleanStdout(t, stdout)
	assertSingleJSONDocument(t, stderr)
}
