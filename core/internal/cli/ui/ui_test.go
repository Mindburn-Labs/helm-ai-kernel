package ui

import (
	"bytes"
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
