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

**Exception — `doctor` / `diag`:** exit 0 = no WARN/FAIL, exit 1 = WARN only,
exit 2 = one or more FAIL. That health ranking is intentional and covered by
doctor tests; do not generalize it to other verbs.

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
  in JSON mode, and the clean text form otherwise. Commands that register
  `--format` route their post-parse error paths through it, keyed off the
  **effective** output mode (i.e. `jsonOut || formatFlag.IsJSON()`, so the
  legacy `--json` alias selects the envelope too). In JSON mode stderr must
  remain exactly one JSON document — gate any supplementary usage lines on
  text mode. `cliui.WriteError` remains the text-mode shorthand.

## Output format: `--format text|json`

Catalog contract: every command except domain-collision verbs (`verify`,
`import`, `skills`) rejects unknown `--format` values before work starts.
Commands that register `--format` themselves (`plan`, `doctor`, `setup`,
`receipts`, …) keep the token so RequestedFormat last-wins still works.
Other operator-data commands rewrite `--format=json` to the legacy `--json`
alias. Listeners, `tui`, `completion`, `onboard`, and `quickstart` still fail
closed on unknown formats; they are exempt from emitting a JSON operator
document.

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
  keep that flag and do NOT consume it at Dispatch.
- JSON payloads are emitted with `cliui.WriteJSON(stdout, v)`.
- `help --json` / `help --format=json` is the generated machine catalog.
  `help --all` prints the same command set.

## Operator TUI

On an interactive TTY, `helm-ai-kernel` with no args (or `tui` / `ui` /
`dashboard`) opens a full-screen operator session. Pipes, `TERM=dumb`,
`HELM_NO_TUI=1`, `--help`, `--json`, and tests keep the text front door.
JSON catalogs, exit codes, `--format`, and typed APPROVE/DENY confirmation
are unchanged.

The TUI is the **operator instrument for a fail-closed execution firewall**,
not a convenience shell and not a chat composer. Overlay grammar may follow
Grok-class chrome; security invariants win when they conflict with convenience.

### Keyboard map

| Key | Action |
| --- | --- |
| `j` / `k` or arrows | Move |
| `1`–`6` | Doctor / Watch / Policy / Freeze / Threat / Catalog (home only) |
| Enter | Open, run, or open ceremony (does **not** APPROVE) |
| `/` | Command catalog filter |
| `r` | Refresh doctor or watch |
| Esc | Close overlay or abort a run |
| Click | Select row or `[x]` — never APPROVE |
| `?` | Show this shortcuts overlay |
| `q` / Ctrl+C | Quit |

Ceremony: type `APPROVE` or `DENY`. Click, `1`–`9`, Enter-on-row, and Ctrl+O
never transition state.

### Security invariants

- **Header** (always): brand, version+commit, Kernel `[WAIT]`/`[PASS]`/`[FAIL]`
  (FAIL if the Kernel is unreachable; never PASS before watch returns),
  pending ceremony count as a security queue (`1 pending ceremony`).
  The TUI catalog ranks Doctor, Watch, Policy, Freeze, Threat, and Incident
  before Get started convenience. Headless `help --all` section order is
  unchanged.
- **Fail-closed defaults**: palette clicks never `--yes`, never freeze/unfreeze
  without `--status`, never start a listener (`server`/`serve --policy`/
  `quickstart`/`dev`/`proxy`). Empty composer argv uses the same
  `DefaultArgs` as the palette. `scan` defaults to `--help`; any non-help
  `scan` (including `--path`) is refused — a cwd walk is unbounded and Esc
  cannot abort Kernel `Run`. Other missing args execute real CLI usage in
  the Output overlay. Composer argv is field-split, never `sh -c`.
- **Destructive confirm**: teardown / freeze-mutate / setup `--yes` / `init`
  and `scaffold` (write `helm/`) / `policy init` (writes `policies/`) /
  `mcp revoke|authorize-call|approve|install|pack|proof|auth-profile put`
  / `incident ack|create` require typing the full invocation. A single key
  never mutates. Palette defaults stay inspect.
- **Secrets**: captured stdout/stderr are redacted before the overlay.
- **Workspace**: Home, Watch, Demo. Overlays (Commands, Doctor, Setup,
  Receipts, Policy/Threat/Incident/MCP pickers, Output, Confirm, Ceremony,
  Shortcuts) float with `[x]`, Esc, and click-to-close.
- **Composer** (always): `>` prompt. `/` filters Commands. Enter executes
  argv in-TUI. After a run, `/` starts another command without quitting.
- **Listeners**: refused in-TUI because cancel cannot reclaim a bind or a
  cwd walk. `onboard` and `setup --quickstart` without `--dry-run` are
  listeners. Non-help `scan` is refused for the same reason. Esc abort
  discards the session result; it does not cancel an in-flight Kernel
  `Run`. No TUI-started listener is left behind.
- **Live inspect**: Doctor, Watch, Setup clients, and Receipts edge
  load on first paint and refresh while those overlays are open. Setup
  rows stay `--dry-run`. Receipts preload is `receipts status` (bounded
  HTTP), never SSE `tail`.

No upgrade CTA. No YOLO. No public GA or “world-class” copy on this surface.

## Receipts front

`receipts` is the canonical inspect surface: `status` / `list` / `show` /
`verify` / `export` / `tail`. `status`, `list`, and `show` are bounded HTTP
(or `--file` for show). `tail` is SSE and is a listener-class verb in the
TUI. `verify` aliases verify receipt. `export --ndjson` emits compact
newline-delimited signed receipt envelopes (verify with
`receipts verify --receipt FILE --trusted-public-key-file KEY`). `export`
without `--ndjson` still aliases EvidencePack export. None invent evidence.

## MCP scan

`mcp scan` inspects configured/local MCP client configs, `--path`, or
`--manifest`. It reports missing pins/hashes and obviously shadowed names as
findings. It does not authorize, ALLOW, or start a listener. `--format
text|json`. Exit 0 if the scan ran; exit 1 only when `--fail-on` is set and
a finding meets that threshold; exit 2 on usage. Doctor may suggest
`mcp scan` and must not add `--yes`. `mcp approve` stays unavailable.

## Policy dialect view

`policy export --dialect cedar|opa` emits a read-only view of CLI-visible
policy records (templates, fixture JSON, or a serve `.toml`). HELM policy
remains authoritative. The view is not a dual-write and does not map the
Kernel PDP, Cedar/IdP interchange, or a live policy store. `--format json`
wraps the document with `source_of_truth: false`.

## Migrated reference slice

Golden tests in `core/cmd/helm-ai-kernel/cli_ui_convention_test.go` and
`format_contract_test.go` pin the flag contract, representative JSON verbs,
and the catalog loop. `core/internal/cli/ui/ui_test.go` pins the helper
contracts. `--format` on collision verbs stays a domain flag.

Doctor and setup repair suggestions share inspect-first, `--dry-run`
defaults. They do not recommend `--yes`.
