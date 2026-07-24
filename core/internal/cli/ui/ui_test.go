package ui

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"testing"
)

// --- Golden: unified --format flag surface --------------------------------

func TestFormatFlagGoldenSurface(t *testing.T) {
	fs := flag.NewFlagSet("golden", flag.ContinueOnError)
	ff := RegisterFormat(fs, FormatText)

	f := fs.Lookup("format")
	if f == nil {
		t.Fatal("--format flag not registered")
	}
	if f.Usage != "Output format: text|json" {
		t.Fatalf("usage text drifted: %q", f.Usage)
	}
	if f.DefValue != "text" {
		t.Fatalf("default drifted: %q", f.DefValue)
	}
	if ff.Value != FormatText {
		t.Fatalf("default value drifted: %q", ff.Value)
	}
}

func TestFormatFlagAcceptsTextAndJSON(t *testing.T) {
	for _, in := range []string{"text", "json", "JSON", " text "} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		ff := RegisterFormat(fs, FormatText)
		if err := fs.Parse([]string{"--format", in}); err != nil {
			t.Fatalf("ParseFormat(%q) rejected: %v", in, err)
		}
		want := Format(strings.ToLower(strings.TrimSpace(in)))
		if ff.Value != want {
			t.Fatalf("ParseFormat(%q) = %q, want %q", in, ff.Value, want)
		}
	}
}

func TestFormatFlagRejectsUnknown(t *testing.T) {
	for _, in := range []string{"yaml", "", "table", "jsonl"} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		var chrome bytes.Buffer
		fs.SetOutput(&chrome)
		RegisterFormat(fs, FormatText)
		if err := fs.Parse([]string{"--format", in}); err == nil {
			t.Fatalf("ParseFormat(%q) accepted unknown format", in)
		} else if !strings.Contains(err.Error(), "expected text|json") {
			t.Fatalf("ParseFormat(%q) error drifted: %v", in, err)
		}
	}
}

func TestParseFormatGoldenErrors(t *testing.T) {
	if _, err := ParseFormat("yaml"); err == nil ||
		err.Error() != `invalid --format "yaml": expected text|json` {
		t.Fatalf("golden error text drifted: %v", err)
	}
}

// --- Golden: CliError formatting ------------------------------------------

func TestFormatErrorGoldenStrings(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"usage with op", UsageErrorf("receipts tail", "--agent is required"),
			"Error: receipts tail: --agent is required"},
		{"usage without op", UsageErrorf("", "unexpected argument: foo"),
			"Error: unexpected argument: foo"},
		{"failure with hint", Failf("verify", "pack signature invalid").
			WithHint("run `helm-ai-kernel verify --bundle <path> --trusted-public-key <hex>`"),
			"Error: verify: pack signature invalid\n  hint: run `helm-ai-kernel verify --bundle <path> --trusted-public-key <hex>`"},
		{"wrapped cause", Wrapf(errors.New("no such file"), ExitUsage, "verify decision-receipt", "read %s", "r.json"),
			"Error: verify decision-receipt: read r.json: no such file"},
		{"plain error", errors.New("boom"), "Error: boom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatError(tc.err); got != tc.want {
				t.Fatalf("FormatError drifted:\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

func TestFormatErrorJSONGolden(t *testing.T) {
	got := FormatErrorJSON(Failf("verify", "pack signature invalid").WithHint("check key"))
	want := `{"error":{"op":"verify","message":"pack signature invalid","hint":"check key","code":1}}`
	if got != want {
		t.Fatalf("JSON envelope drifted:\n got: %s\nwant: %s", got, want)
	}
	got = FormatErrorJSON(errors.New("boom"))
	want = `{"error":{"message":"boom","code":1}}`
	if got != want {
		t.Fatalf("plain JSON envelope drifted:\n got: %s\nwant: %s", got, want)
	}
}

// --- Golden: exit codes (fail closed) -------------------------------------

func TestExitCodeGolden(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{nil, ExitOK},
		{UsageErrorf("x", "bad flag"), ExitUsage},
		{Failf("x", "boom"), ExitFailure},
		{errors.New("boom"), ExitFailure},
		{fmt.Errorf("wrap: %w", UsageErrorf("x", "bad")), ExitUsage},
		{&CliError{Code: 0, Msg: "forged zero"}, ExitFailure},    // fail closed
		{&CliError{Code: 255, Msg: "out of range"}, ExitFailure}, // fail closed
	}
	for i, tc := range cases {
		if got := ExitCode(tc.err); got != tc.want {
			t.Fatalf("case %d: ExitCode = %d, want %d", i, got, tc.want)
		}
	}
}

// --- Golden: stream discipline --------------------------------------------

func TestWriteErrorKeepsDataStreamClean(t *testing.T) {
	var data, chrome bytes.Buffer
	s := NewStreams(&data, &chrome)

	code := WriteError(s.Chrome, UsageErrorf("receipts tail", "--agent is required"))
	if code != ExitUsage {
		t.Fatalf("exit code = %d, want %d", code, ExitUsage)
	}
	if data.Len() != 0 {
		t.Fatalf("data stream polluted: %q", data.String())
	}
	if got := chrome.String(); got != "Error: receipts tail: --agent is required\n" {
		t.Fatalf("chrome output drifted: %q", got)
	}
}

func TestWriteErrorNilIsSilentSuccess(t *testing.T) {
	var chrome bytes.Buffer
	if code := WriteError(&chrome, nil); code != ExitOK || chrome.Len() != 0 {
		t.Fatalf("nil error wrote %q with code %d", chrome.String(), code)
	}
}

func TestCliErrorUnwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := Wrapf(cause, ExitFailure, "op", "ctx")
	if !errors.Is(err, cause) {
		t.Fatal("Unwrap broken: errors.Is could not find cause")
	}
}

func TestWriteJSONGolden(t *testing.T) {
	var data bytes.Buffer
	if err := WriteJSON(&data, map[string]string{"status": "ok"}); err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"status\": \"ok\"\n}\n"
	if data.String() != want {
		t.Fatalf("JSON output drifted:\n got: %q\nwant: %q", data.String(), want)
	}
}

// --- Regression: nil-safe WithHint (permit advisory P3) --------------------

func TestWithHintNilReceiverIsSafe(t *testing.T) {
	// Wrapf returns nil for a nil cause; chaining WithHint must not panic.
	err := Wrapf(nil, ExitFailure, "op", "ctx").WithHint("try again")
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	var nilErr *CliError
	if got := nilErr.WithHint("x"); got != nil {
		t.Fatalf("nil receiver WithHint = %v, want nil", got)
	}
}

// --- Golden: format-aware WriteError (permit advisory P3) ------------------

func TestWriteErrorFormatGolden(t *testing.T) {
	var chrome bytes.Buffer
	err := Failf("verify", "pack signature invalid").WithHint("check key")

	code := WriteErrorFormat(&chrome, err, FormatJSON)
	if code != ExitFailure {
		t.Fatalf("exit code = %d, want %d", code, ExitFailure)
	}
	want := `{"error":{"op":"verify","message":"pack signature invalid","hint":"check key","code":1}}` + "\n"
	if chrome.String() != want {
		t.Fatalf("JSON envelope drifted:\n got: %q\nwant: %q", chrome.String(), want)
	}

	chrome.Reset()
	code = WriteErrorFormat(&chrome, err, FormatText)
	if code != ExitFailure {
		t.Fatalf("exit code = %d, want %d", code, ExitFailure)
	}
	want = "Error: verify: pack signature invalid\n  hint: check key\n"
	if chrome.String() != want {
		t.Fatalf("text form drifted:\n got: %q\nwant: %q", chrome.String(), want)
	}

	// WriteError stays the text-mode shorthand.
	chrome.Reset()
	if WriteError(&chrome, err) != ExitFailure || chrome.String() != want {
		t.Fatalf("WriteError shorthand drifted: %q", chrome.String())
	}

	// Nil error stays silent under both formats.
	chrome.Reset()
	if WriteErrorFormat(&chrome, nil, FormatJSON) != ExitOK || chrome.Len() != 0 {
		t.Fatalf("nil error wrote %q", chrome.String())
	}
}

// --- Regression: envelope message with empty-Msg wrap (permit round-4 P3) --

func TestFormatErrorJSONEmptyMsgWrap(t *testing.T) {
	got := FormatErrorJSON(Wrapf(errors.New("bundle digest mismatch"), ExitUsage, "verify decision-receipt", ""))
	want := `{"error":{"op":"verify decision-receipt","message":"bundle digest mismatch","code":2}}`
	if got != want {
		t.Fatalf("empty-Msg envelope drifted:\n got: %s\nwant: %s", got, want)
	}
}

// --- Golden: RequestedFormat + ParseFlags (permit round-5 P2) --------------

// vf builds a value-flag set for scanner tests.
func vf(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

func TestRequestedFormatGolden(t *testing.T) {
	cases := []struct {
		args []string
		want Format
	}{
		{[]string{"--format=json"}, FormatJSON},
		{[]string{"--format", "json"}, FormatJSON},
		{[]string{"-format", "text"}, FormatText},
		{[]string{"--json"}, FormatJSON},
		{[]string{"--json=false"}, FormatText},
		{[]string{"--json=true"}, FormatJSON},
		{[]string{"--bogus", "--json"}, FormatJSON}, // mode survives unknown flags
		{[]string{"--format", "yaml"}, FormatText},  // invalid value fails closed to default
		{[]string{"--effect", "X"}, FormatText},
		{[]string{"json"}, FormatText},                           // positional never flips mode
		{[]string{"--effect", "json", "--bogus"}, FormatText},    // flag value never flips mode
		{[]string{"--", "--json"}, FormatText},                   // after -- everything is positional
		{[]string{"--format=json", "--format=text"}, FormatText}, // last wins, like flag
	}
	for i, tc := range cases {
		if got := RequestedFormat(tc.args, FormatText, vf("effect", "format"), true); got != tc.want {
			t.Fatalf("case %d %v: got %q want %q", i, tc.args, got, tc.want)
		}
	}
}

func TestParseFlagsJSONModeParseError(t *testing.T) {
	fs := flag.NewFlagSet("risk-summary", flag.ContinueOnError)
	RegisterFormat(fs, FormatText)
	var chrome bytes.Buffer
	code, ok := ParseFlags(fs, []string{"--format=json", "--bogus"}, &chrome, "risk-summary", FormatText)
	if ok || code != ExitUsage {
		t.Fatalf("code=%d ok=%v", code, ok)
	}
	got := strings.TrimSpace(chrome.String())
	var doc map[string]any
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("parse error not a JSON document: %v\n%s", err, got)
	}
	errBody, _ := doc["error"].(map[string]any)
	if !strings.Contains(errBody["message"].(string), "flag provided but not defined: -bogus") {
		t.Fatalf("envelope message drifted: %s", got)
	}
}

func TestParseFlagsTextModeAndHelp(t *testing.T) {
	// Text mode: clean human error, flag-package noise suppressed.
	fs := flag.NewFlagSet("risk-summary", flag.ContinueOnError)
	RegisterFormat(fs, FormatText)
	var chrome bytes.Buffer
	code, ok := ParseFlags(fs, []string{"--bogus"}, &chrome, "risk-summary", FormatText)
	if ok || code != ExitUsage {
		t.Fatalf("code=%d ok=%v", code, ok)
	}
	if chrome.String() != "Error: risk-summary: flag provided but not defined: -bogus\n" {
		t.Fatalf("text parse error drifted: %q", chrome.String())
	}

	// -h keeps the historical usage dump on chrome with exit code 2.
	fs = flag.NewFlagSet("risk-summary", flag.ContinueOnError)
	RegisterFormat(fs, FormatText)
	chrome.Reset()
	code, ok = ParseFlags(fs, []string{"-h"}, &chrome, "risk-summary", FormatText)
	if ok || code != ExitUsage {
		t.Fatalf("-h code=%d ok=%v", code, ok)
	}
	if !strings.Contains(chrome.String(), "Usage of risk-summary:") || !strings.Contains(chrome.String(), "-format value") {
		t.Fatalf("help output drifted: %q", chrome.String())
	}

	// Success path.
	fs = flag.NewFlagSet("risk-summary", flag.ContinueOnError)
	ff := RegisterFormat(fs, FormatText)
	chrome.Reset()
	if code, ok = ParseFlags(fs, []string{"--format=json"}, &chrome, "risk-summary", FormatText); !ok || code != ExitOK {
		t.Fatalf("success code=%d ok=%v", code, ok)
	}
	if !ff.IsJSON() || chrome.Len() != 0 {
		t.Fatalf("success side effects wrong: ff=%v chrome=%q", ff.Value, chrome.String())
	}
}

// --- Regression: flag-value-aware scan (permit round-7 P2) -----------------

func TestRequestedFormatSkipsFlagValues(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want Format
	}{
		{"reviewer example", []string{"--format=json", "--effect", "--format=text", "--bogus"}, FormatJSON},
		{"selector as effect value", []string{"--effect", "--format=json", "--bogus"}, FormatText},
		{"json as effect value", []string{"--effect", "--json", "--bogus"}, FormatText},
		{"selector after value flag", []string{"--effect", "INFRA_DESTROY", "--format=json"}, FormatJSON},
		{"embedded value not skipped", []string{"--effect=INFRA_DESTROY", "--format=json"}, FormatJSON},
		{"last valid selector wins", []string{"--format=text", "--effect", "X", "--format=json"}, FormatJSON},
		{"value flag at end no panic", []string{"--effect"}, FormatText},
		{"format value consumed not selector", []string{"--format", "--json"}, FormatText}, // --json is format's value: invalid, fails closed
		{"agent value then json", []string{"--agent", "--format=json"}, FormatText},
		{"json after agent value", []string{"--agent", "a1", "--json"}, FormatJSON},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RequestedFormat(tc.args, FormatText, vf("effect", "format", "agent"), true); got != tc.want {
				t.Fatalf("RequestedFormat(%v) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

// --- Regression: command-aware scan (permit round-8 P2) --------------------

func TestValueFlagNamesDerivesFromFlagSet(t *testing.T) {
	fs := flag.NewFlagSet("risk-summary", flag.ContinueOnError)
	var effect string
	var list, jsonOut bool
	fs.StringVar(&effect, "effect", "", "")
	fs.BoolVar(&list, "list", false, "")
	fs.BoolVar(&jsonOut, "json", false, "")
	RegisterFormat(fs, FormatText)
	names := ValueFlagNames(fs)
	if !names["effect"] || !names["format"] {
		t.Fatalf("value flags missing: %v", names)
	}
	if names["list"] || names["json"] {
		t.Fatalf("bool flags misclassified: %v", names)
	}
}

func TestRequestedFormatCommandAware(t *testing.T) {
	riskFlags := vf("effect", "format") // risk-summary has NO --agent
	// --agent is undefined on risk-summary: the flag package stops there, so
	// the trailing --format=json is a valid selector position and wins.
	if got := RequestedFormat([]string{"--agent", "--format=json"}, FormatText, riskFlags, true); got != FormatJSON {
		t.Fatalf("cross-command name consumed a token: got %q", got)
	}
	// But on receipts tail, --agent IS a value flag and consumes the selector.
	if got := RequestedFormat([]string{"--agent", "--format=json"}, FormatText, vf("agent", "format"), true); got != FormatText {
		t.Fatalf("own value flag failed to consume: got %q", got)
	}
}

// --- Regression: collision-exception --format (permit round-9 P2) ----------

func TestParseFlagsCollisionFormatNotSelector(t *testing.T) {
	// verify decision-receipt registers --format as a STRING (receipt format
	// id), so it must never act as an output selector: --json stays in force.
	fs := flag.NewFlagSet("verify decision-receipt", flag.ContinueOnError)
	var formatID string
	var jsonOut bool
	fs.StringVar(&formatID, "format", "", "receipt format id")
	fs.BoolVar(&jsonOut, "json", false, "")
	var chrome bytes.Buffer
	code, ok := ParseFlags(fs, []string{"--json", "--format", "text", "--bogus"}, &chrome, "verify decision-receipt", FormatText)
	if ok || code != ExitUsage {
		t.Fatalf("code=%d ok=%v", code, ok)
	}
	got := strings.TrimSpace(chrome.String())
	var doc map[string]any
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("collision --format misread as selector; not JSON: %v\n%s", err, got)
	}

	// And with a RegisterFormat-registered --format, it IS the selector.
	fs2 := flag.NewFlagSet("risk-summary", flag.ContinueOnError)
	RegisterFormat(fs2, FormatText)
	chrome.Reset()
	code, ok = ParseFlags(fs2, []string{"--format=json", "--bogus"}, &chrome, "risk-summary", FormatText)
	if ok || code != ExitUsage {
		t.Fatalf("code=%d ok=%v", code, ok)
	}
	got = strings.TrimSpace(chrome.String())
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("selector --format not honored: %v\n%s", err, got)
	}
}
