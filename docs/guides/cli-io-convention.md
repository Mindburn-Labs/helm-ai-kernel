# CLI I/O Convention (helm-ai-kernel)

Status: **active convention** — introduced with the W4 reference slice. All new
commands must follow it; existing commands migrate incrementally.

Shared implementation: `core/internal/cli/ui` (import as `cliui`).

## Streams

- **stdout is data.** Anything a pipeline might consume — JSON, ids, tables —
  goes to stdout and nothing else does. `helm-ai-kernel … 2>/dev/null | jq .`
  must always work.
- **stderr is chrome.** Usage text, progress, warnings, prompts, and errors go
  to stderr.
- Command handlers already receive `(args, stdout, stderr)`; never write to
  `os.Stdout`/`os.Stderr` directly (spawning a child process that inherits
  them is the only tolerated exception).

## Exit codes

| Code | Meaning                                             |
| ---- | --------------------------------------------------- |
| 0    | success                                             |
| 1    | operational failure (verification failed, I/O, …)   |
| 2    | usage error (bad/missing flags, bad arguments)      |

These codes are load-bearing for scripts and must not change per command.

## Errors: `cliui.CliError`

User-facing errors are `*cliui.CliError` values rendered by the single
formatter — one clean line, optional remediation hint, **never** a stack
trace:

```go
return cliui.WriteError(stderr, cliui.UsageErrorf("receipts tail", "--agent is required"))
// stderr: Error: receipts tail: --agent is required   (exit 2)

return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "log sth", "signing tree head"))
// stderr: Error: log sth: signing tree head: <cause>   (exit 1)

return cliui.WriteError(stderr, cliui.UsageErrorf("trust", "unknown subcommand: %s", name).
    WithHint("run `helm-ai-kernel trust help`"))
// stderr: Error: trust: unknown subcommand: bogus
//           hint: run `helm-ai-kernel trust help`      (exit 2)
```

- `cliui.UsageErrorf` → exit 2, `cliui.Failf` → exit 1, `cliui.Wrapf` wraps a
  cause (and returns nil for nil err).
- `cliui.ExitCode` fails closed: unknown error types and out-of-range codes
  map to 1, never 0.
- `cliui.WriteErrorFormat(w, err, format)` renders the stable machine envelope
  `{"error":{"op","message","hint","code"}}` on stderr when the command runs
  with `--format=json`, and the clean text form otherwise. Commands that
  register `--format` route their post-parse error paths through it.
  `cliui.WriteError` remains the text-mode shorthand.

## Output format: `--format text|json`

Commands with machine-readable output register the unified flag:

```go
formatFlag := cliui.RegisterFormat(cmd, cliui.FormatText) // adds --format text|json
// after Parse:
jsonOut = jsonOut || formatFlag.IsJSON() // keep legacy --json as an alias
```

Rules:

- Unknown values are rejected (`invalid --format "yaml": expected text|json`,
  exit 2). There is no silent fallback.
- The legacy `--json` bool stays as an alias wherever it already exists;
  removing it is a separate, explicitly-flagged breaking change.
- **Collision exception:** if a command already uses `--format` for a
  different meaning (e.g. `verify decision-receipt --format <receipt-format-id>`),
  keep that flag and do NOT register the output-format flag on that command.
- JSON payloads are emitted with `cliui.WriteJSON(stdout, v)`.

## Migrated reference slice (Wave 1)

`receipts`, `risk-summary`, `verify decision-receipt`, `verify --entry`,
`scan`, `trust`, `export aat`, `log`, `plan` — 9 commands. Golden tests in
`core/cmd/helm-ai-kernel/cli_ui_convention_test.go` pin their flag surface,
error text, and stream discipline; `core/internal/cli/ui/ui_test.go` pins the
helper contracts. `--format` is registered on `receipts tail`, `risk-summary`,
`verify --entry`, `trust eu-list status`, and `plan compile` (whose output is
PlanSpec-JSON-only; `--format=text` is a no-op there, matching the historical
`--json=false` quirk).

## Fan-out checklist (follow-up PRs, leaf-first)

1. Pick a command file; read its existing tests for pinned output.
2. Replace `fmt.Fprintf(stderr, "Error: …")` + bare `return N` with
   `cliui.WriteError(...)` using the same exit code.
3. If the command has `--json`, register `--format` and OR it in; keep `--json`.
4. Move any stray stdout chrome (warnings, summaries) to stderr.
5. Add a golden case to `cli_ui_convention_test.go`.
6. Do not batch more than ~10 commands per PR.
