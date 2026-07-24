// Package ui defines the shared I/O discipline for the helm-ai-kernel CLI.
//
// Convention (see docs/guides/cli-io-convention.md):
//
//   - Data goes to stdout (Streams.Data) and ONLY data: anything a pipeline
//     may consume (JSON, tables, ids) must be parseable when stderr is
//     discarded.
//   - Chrome goes to stderr (Streams.Chrome): usage text, progress,
//     warnings, prompts, and errors.
//   - Errors are structured *CliError values rendered by FormatError /
//     WriteError: one clean line, an optional remediation hint, and never a
//     stack trace for user-facing errors.
//   - Exit codes: 0 success, 1 operational failure, 2 usage error.
//     Unknown errors fail closed to 1; unknown --format values are rejected.
//
// The helpers are additive and opt-in per command; existing flags, output
// text, and exit codes are preserved unless a command explicitly migrates.
package ui

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Exit codes used across the CLI. These match the historical kernel
// convention (2 = usage error, 1 = operational failure) and must not change.
const (
	ExitOK      = 0
	ExitFailure = 1
	ExitUsage   = 2
)

// maxExitCode bounds codes accepted from a CliError. Anything outside
// 1..maxExitCode fails closed to ExitFailure so a programming mistake can
// never masquerade as success or as a shell-reserved status.
const maxExitCode = 125

// Streams pairs the two output channels of a command.
type Streams struct {
	// Data receives machine-consumable output (stdout).
	Data io.Writer
	// Chrome receives human scaffolding: usage, progress, warnings, errors (stderr).
	Chrome io.Writer
}

// NewStreams builds a Streams from explicit writers (used by tests and by the
// Run(args, stdout, stderr) dispatcher).
func NewStreams(data, chrome io.Writer) Streams {
	return Streams{Data: data, Chrome: chrome}
}

// Std returns the process streams.
func Std() Streams {
	return Streams{Data: os.Stdout, Chrome: os.Stderr}
}

// Format is the unified output-format convention: text|json.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// IsJSON reports whether the format selects JSON output.
func (f Format) IsJSON() bool { return f == FormatJSON }

// ParseFormat validates an explicit format string. Unknown values are
// rejected (fail closed); there is no silent fallback to text.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case FormatText:
		return FormatText, nil
	case FormatJSON:
		return FormatJSON, nil
	default:
		return "", fmt.Errorf("invalid --format %q: expected text|json", s)
	}
}

// FormatFlag is a flag.Value for --format text|json. The default is FormatText.
type FormatFlag struct {
	Value Format
}

// NewFormatFlag returns a FormatFlag with the given default. An empty or
// invalid default fails closed to FormatText.
func NewFormatFlag(def Format) *FormatFlag {
	if def != FormatJSON {
		def = FormatText
	}
	return &FormatFlag{Value: def}
}

// String implements flag.Value.
func (f *FormatFlag) String() string {
	if f == nil || f.Value == "" {
		return string(FormatText)
	}
	return string(f.Value)
}

// IsJSON reports whether the flag currently selects JSON output.
func (f *FormatFlag) IsJSON() bool { return f != nil && f.Value.IsJSON() }

// Set implements flag.Value, rejecting unknown formats.
func (f *FormatFlag) Set(s string) error {
	v, err := ParseFormat(s)
	if err != nil {
		return err
	}
	f.Value = v
	return nil
}

// RegisterFormat adds a unified --format text|json flag to fs and returns
// its handle. Commands that already use --format for a different meaning
// (e.g. receipt format ids) must NOT call this; keep their existing flag.
func RegisterFormat(fs *flag.FlagSet, def Format) *FormatFlag {
	ff := NewFormatFlag(def)
	fs.Var(ff, "format", "Output format: text|json")
	return ff
}

// CliError is the structured command error. It carries a clean message, an
// optional remediation hint, an optional wrapped cause, and an exit code.
// It never exposes stack noise for user-facing failures.
type CliError struct {
	// Code is the process exit code (ExitUsage or ExitFailure for constructors).
	Code int
	// Op names the failing operation (e.g. "receipts tail"). Optional.
	Op string
	// Msg is the clean user-facing message.
	Msg string
	// Hint is an optional remediation line ("Did you mean", exact fix command).
	Hint string
	// Err is the optional wrapped cause.
	Err error
}

// UsageErrorf builds a *CliError with exit code 2 (usage error).
func UsageErrorf(op, format string, args ...any) *CliError {
	return &CliError{Code: ExitUsage, Op: op, Msg: fmt.Sprintf(format, args...)}
}

// Failf builds a *CliError with exit code 1 (operational failure).
func Failf(op, format string, args ...any) *CliError {
	return &CliError{Code: ExitFailure, Op: op, Msg: fmt.Sprintf(format, args...)}
}

// Wrapf builds a *CliError wrapping a cause. A nil cause yields nil so call
// sites can use `return ui.WriteError(w, ui.Wrapf(err, ...))` unconditionally.
func Wrapf(err error, code int, op, format string, args ...any) *CliError {
	if err == nil {
		return nil
	}
	return &CliError{Code: code, Op: op, Msg: fmt.Sprintf(format, args...), Err: err}
}

// WithHint attaches a remediation hint and returns the error for chaining.
// It is nil-safe: chaining onto Wrapf (nil for a nil cause) returns nil
// instead of panicking.
func (e *CliError) WithHint(hint string) *CliError {
	if e == nil {
		return nil
	}
	e.Hint = hint
	return e
}

// Error returns the single-line form: "op: msg: cause" (empty segments skipped).
func (e *CliError) Error() string {
	parts := make([]string, 0, 3)
	if e.Op != "" {
		parts = append(parts, e.Op)
	}
	if e.Msg != "" {
		parts = append(parts, e.Msg)
	}
	if e.Err != nil {
		parts = append(parts, e.Err.Error())
	}
	return strings.Join(parts, ": ")
}

// Unwrap exposes the wrapped cause for errors.Is/As.
func (e *CliError) Unwrap() error { return e.Err }

// ExitCode maps an error to a process exit code. nil → 0; *CliError → its
// code (sanitized, fail closed); anything else → ExitFailure.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var ce *CliError
	if errors.As(err, &ce) {
		if ce.Code >= ExitFailure && ce.Code <= maxExitCode {
			return ce.Code
		}
		return ExitFailure
	}
	return ExitFailure
}

// FormatError renders err as clean chrome text: an "Error: ..." line plus an
// optional "  hint: ..." line. Plain (non-CliError) errors are rendered
// without op/hint decoration. No stack traces, ever.
func FormatError(err error) string {
	if err == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("Error: ")
	b.WriteString(err.Error())
	var ce *CliError
	if errors.As(err, &ce) && ce.Hint != "" {
		b.WriteString("\n  hint: ")
		b.WriteString(ce.Hint)
	}
	return b.String()
}

// errorEnvelope is the structured JSON error form for --format=json consumers.
type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Op      string `json:"op,omitempty"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	Code    int    `json:"code"`
}

// FormatErrorJSON renders err as a stable JSON envelope for machine consumers.
func FormatErrorJSON(err error) string {
	body := errorBody{Message: err.Error(), Code: ExitCode(err)}
	var ce *CliError
	if errors.As(err, &ce) {
		body.Op = ce.Op
		body.Hint = ce.Hint
		// Join non-empty segments only: an empty Msg (Wrapf with an empty
		// format) must not yield a leading ": ".
		switch {
		case ce.Msg != "" && ce.Err != nil:
			body.Message = ce.Msg + ": " + ce.Err.Error()
		case ce.Msg != "":
			body.Message = ce.Msg
		case ce.Err != nil:
			body.Message = ce.Err.Error()
		default:
			body.Message = ce.Op
		}
	}
	data, err := json.Marshal(errorEnvelope{Error: body})
	if err != nil {
		// Fail closed: envelope fields are plain strings, so this is unreachable
		// in practice; degrade to an inline literal rather than dropping the error.
		return `{"error":{"message":"error encoding failure","code":1}}`
	}
	return string(data)
}

// WriteError writes FormatError(err) plus a trailing newline to chrome and
// returns the exit code for err, so handlers can `return ui.WriteError(...)`.
// A nil err writes nothing and returns ExitOK.
func WriteError(chrome io.Writer, err error) int {
	return WriteErrorFormat(chrome, err, FormatText)
}

// WriteErrorFormat is WriteError with format-aware rendering: under
// FormatJSON it emits the stable {"error":{...}} envelope (FormatErrorJSON)
// so --format=json consumers get structured errors on stderr; otherwise it
// renders the clean text form. Data/chrome separation is unchanged — errors
// always go to chrome (stderr), never to the data stream.
func WriteErrorFormat(chrome io.Writer, err error, f Format) int {
	if err == nil {
		return ExitOK
	}
	if f.IsJSON() {
		_, _ = fmt.Fprintln(chrome, FormatErrorJSON(err))
	} else {
		_, _ = fmt.Fprintln(chrome, FormatError(err))
	}
	return ExitCode(err)
}

// WriteJSON encodes v as indented JSON to the data stream. It is the
// standard way to emit --format=json payloads.
func WriteJSON(data io.Writer, v any) error {
	enc := json.NewEncoder(data)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ValueFlagNames derives the set of value-taking flags (anything that is not
// a bool flag) from the command's OWN FlagSet, using the flag package's
// boolFlag convention. The scan is command-aware by construction: a name
// that is not registered on this command never consumes the following token.
func ValueFlagNames(fs *flag.FlagSet) map[string]bool {
	names := map[string]bool{}
	fs.VisitAll(func(fl *flag.Flag) {
		if bf, ok := fl.Value.(interface{ IsBoolFlag() bool }); !ok || !bf.IsBoolFlag() {
			names[fl.Name] = true
		}
	})
	return names
}

// RequestedFormat best-effort scans raw CLI args for an explicit output-mode
// selection (--format=<v> | --format <v> | --json[=bool]) so a flag-parse
// error can still be rendered in the mode the user asked for. The scan is
// flag-aware and command-aware: it stops at the `--` terminator, ignores
// bare positionals, and skips the value positions of the command's own
// value-taking flags (valueFlags, see ValueFlagNames), so a token consumed
// as another flag's value (e.g. `--effect --format=text`) never flips the
// mode — while a value-flag name belonging to a DIFFERENT command (unknown
// here) does not consume anything, matching the flag package's
// stop-at-first-undefined-flag behavior. The last selector in a valid flag
// position wins. Invalid or missing values fail closed to def.
func RequestedFormat(args []string, def Format, valueFlags map[string]bool) Format {
	f := def
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			break // everything after the terminator is positional
		}
		if !strings.HasPrefix(args[i], "-") || args[i] == "-" {
			continue
		}
		name := strings.TrimLeft(args[i], "-")
		switch {
		case name == "json":
			f = FormatJSON
		case strings.HasPrefix(name, "json="):
			if v, err := strconv.ParseBool(strings.TrimPrefix(name, "json=")); err == nil {
				if v {
					f = FormatJSON
				} else {
					f = FormatText
				}
			}
		case name == "format" && i+1 < len(args):
			if v, err := ParseFormat(args[i+1]); err == nil {
				f = v
			}
			i++
		case strings.HasPrefix(name, "format="):
			if v, err := ParseFormat(strings.TrimPrefix(name, "format=")); err == nil {
				f = v
			}
		case valueFlags[name]:
			i++ // the next token is this flag's value, never a selector
		}
	}
	return f
}

// ParseFlags parses args with the flag package's own diagnostics suppressed
// and renders failures through the single formatter in the user's requested
// output mode (RequestedFormat seeded with def) — keeping JSON-mode stderr
// exactly one document even when the failure is a malformed flag. def must
// be the command's own default output mode: FormatText for ordinary
// commands, FormatJSON for JSON-only commands such as plan compile (whose
// --json defaults to true). It returns (0, true) on success. On failure it
// has already written the error to chrome and returns (ExitUsage, false):
//
//	if code, ok := cliui.ParseFlags(cmd, args, stderr, "risk-summary", cliui.FormatText); !ok {
//		return code
//	}
//
// -h/--help reproduces the flag package's historical usage dump on chrome
// (always text) and returns the same exit code (2) as the previous direct
// `cmd.Parse` + `return 2` pattern.
func ParseFlags(fs *flag.FlagSet, args []string, chrome io.Writer, op string, def Format) (int, bool) {
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintf(chrome, "Usage of %s:\n", fs.Name())
			fs.SetOutput(chrome)
			fs.PrintDefaults()
			return ExitUsage, false
		}
		return WriteErrorFormat(chrome, UsageErrorf(op, "%s", err), RequestedFormat(args, def, ValueFlagNames(fs))), false
	}
	return ExitOK, true
}
