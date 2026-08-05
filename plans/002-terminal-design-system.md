# Plan 002: Establish the accessible HELM terminal design system

<!-- reconciled status overlay begins -->
> **Reconciled status — PARTIAL:** against source base
> `075bf090240f436b4dad8e458e4a5f35b97aa4b9` on 2026-08-05, terminal
> capability detection, semantic rendering primitives, and a reviewed
> confirmation slice are present. Remaining gaps are exact: `doctor` still
> uses command-local emoji/raw styling and byte-count padding; the documented
> shared I/O adoption remains an additive nine-command wave; and the planned
> generic `Confirm` and `Select` interaction helpers are not present. This
> is source-planning reconciliation only, not release, deployed, runtime, or
> production evidence.
>
> **Historical plan body:** the executor instructions, audit facts, and
> checkboxes below were authored against `37b7eabe` on 2026-07-31. They are
> retained for provenance and are not current-state or release evidence.
<!-- reconciled status overlay ends -->

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before continuing. If a
> STOP condition occurs, stop and report; do not improvise. Update this plan's
> row in `plans/README.md` when done.
>
> **Drift check (run first)**:
> `git diff --stat 37b7eabe..HEAD -- core/internal/cli/ui core/cmd/helm-ai-kernel/cli_support.go core/cmd/helm-ai-kernel/main.go core/cmd/helm-ai-kernel/doctor_cmd.go core/go.mod core/go.sum`
> Compare changed in-scope behavior with the current-state section. A semantic
> mismatch is a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: `plans/001-cli-safety-and-help.md`
- **Category**: dx, accessibility, direction, tests
- **Planned at**: commit `37b7eabe`, 2026-07-31
- **Linear**: [HELM-427](https://linear.app/mindburn/issue/HELM-427)

## Why this matters

HELM currently has dozens of command-local colors, emoji, layouts, and status
phrases. ANSI escapes are emitted to files and pipes, `NO_COLOR` and
`TERM=dumb` are ignored, and status is sometimes communicated only by color or
emoji. The requested WorkOS/Claude/Codex quality comes from a coherent state
language—progress, choice, authority, evidence, next action—not decorative
output. This plan creates that language once for setup and every later command.

## Current state

- `core/internal/cli/ui/ui.go:1-17` defines the correct stream/error contract
  but says adoption is additive and opt-in.
- `ui.go:44-60` has only `Streams`; it has no terminal capability or semantic
  renderer.
- `core/cmd/helm-ai-kernel/main.go:134-145` defines global raw ANSI constants.
  They are used without checking the output destination.
- `core/cmd/helm-ai-kernel/doctor_cmd.go:150-200` combines emoji and hard-coded
  colors for status; plain text lacks stable `[PASS]`, `[WARN]`, `[FAIL]`
  labels.
- Running the exact audit binary with `NO_COLOR=1` or `TERM=dumb` still emitted
  `\x1b` sequences.
- `github.com/mattn/go-isatty v0.0.20` is already present indirectly in
  `core/go.mod`; do not add a new terminal framework for capability detection.
- PR #679 adds Bubble Tea for the explicit `workstation watch` TUI. That does
  not justify using full-screen rendering for ordinary CLI commands.

## Target visual language

Interactive first run should use a compact form of the screenshot pattern:

```text
HELM
Govern agent actions. Prove every decision.

│  [OK] Detected Claude Code 2.x
│  [OK] Selected local project scope
│  [..] Installing MCP boundary
│  [--] Hook activation pending

┌ HELM is active ──────────────────────────────────┐
│ Agent client  Claude Code                        │
│ Scope         this project                       │
│ Evidence      ~/.helm-ai-kernel/receipts         │
│ Next          helm-ai-kernel receipts tail       │
└──────────────────────────────────────────────────┘
```

The Unicode line and box glyphs are optional decoration. Plain mode renders the
same words with ASCII and preserves every state and next action.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| UI unit tests | `cd core && go test ./internal/cli/ui -count=1` | exit 0 |
| CLI golden tests | `cd core && go test ./cmd/helm-ai-kernel -run 'Test(FrontDoor|Terminal|DoctorRendering|NoColor)' -count=1` | exit 0 |
| CLI suite | `make test-cli` | exit 0 |
| Windows compile | `cd core && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test ./internal/cli/ui ./cmd/helm-ai-kernel -run '^$'` | exit 0 |
| Formatting | `cd core && test -z "$(gofmt -l internal/cli/ui cmd/helm-ai-kernel)"` | exit 0 |

## Scope

**In scope**:

- `core/internal/cli/ui/ui.go`
- `core/internal/cli/ui/terminal.go` (create)
- `core/internal/cli/ui/render.go` (create)
- `core/internal/cli/ui/prompt.go` (create)
- `core/internal/cli/ui/ui_test.go`
- `core/internal/cli/ui/terminal_test.go` (create)
- `core/internal/cli/ui/render_test.go` (create)
- `core/cmd/helm-ai-kernel/cli_support.go`
- `core/cmd/helm-ai-kernel/main.go`
- `core/cmd/helm-ai-kernel/doctor_cmd.go`
- `core/cmd/helm-ai-kernel/main_test.go`
- `core/cmd/helm-ai-kernel/doctor_security_test.go`
- `core/go.mod`, `core/go.sum`
- `docs/guides/cli-io-convention.md`

**Out of scope**:

- A theme marketplace, custom RGB editor, terminal animations, mouse support,
  or persistent full-screen shell.
- Rewriting PR #679's fail-closed workstation watch state model. Its view must
  still adopt this renderer and its authority actions require a separate
  contextual confirmation before release.
- Migrating all commands; Plan 004 owns the fan-out.
- Changing JSON schemas or exit codes.

## Git workflow

- Worktree: `helm-ai-kernel-wt-cli-terminal-design` from live `origin/main`.
- Branch: `codex/cli-terminal-design`.
- Suggested commits: `feat(cli): add accessible terminal renderer` and
  `refactor(cli): render front door and doctor semantically`.
- Re-query PR #679 before touching `go.mod`; if it landed first, use its exact
  dependency versions and do not duplicate terminal helpers.

## Steps

### Step 1: Model terminal capabilities explicitly

Add a small `Capabilities` value containing `Interactive`, `Color`, `Unicode`,
and `Width`. Production detection must:

- enable interaction only when stdin and the chrome writer are terminals;
- disable color when chrome is not a TTY, `NO_COLOR` is non-empty,
  `TERM=dumb`, or the global override requests never;
- permit an explicit always-color override only for a human caller, never for
  JSON mode;
- degrade Unicode when terminal capability is unknown or dumb;
- cap layouts to deterministic compact and wide breakpoints rather than
  reproducing arbitrary terminal widths in golden output.

Use `go-isatty`, already in the module graph, for OS-compatible file descriptor
detection. Keep a constructor that accepts explicit capabilities for tests;
never make unit tests depend on the test runner's TTY.

**Verify**: `cd core && go test ./internal/cli/ui -run TestCapabilities -count=1` → table cases cover pipe, TTY, `NO_COLOR`, `TERM=dumb`, explicit never/always, JSON, and Windows build.

### Step 2: Add semantic rendering primitives

Implement only the primitives the target journeys need:

- semantic roles: brand, muted, success, warning, failure, deny, escalate,
  evidence, command, and selection;
- `Heading`, `Step`, `KeyValue`, `Callout`, and `NextAction` renderers;
- a compact completion card with ASCII fallback;
- visible text labels (`OK`, `WARN`, `FAIL`, `DENY`, `ESCALATE`, `WAIT`) so
  color/glyph is never the sole signal;
- safe width calculation for multi-byte text; avoid manual byte-length padding.

Do not expose raw ANSI constants to commands. Rendering functions decide
whether to style. No spinner is required: a stable `[..]` running state works
in terminals, logs, screen readers, and recordings.

**Verify**: `cd core && go test ./internal/cli/ui -run 'Test(Render|Plain|Width)' -count=1` → golden cases exist for color TTY, no-color TTY, pipe, dumb terminal, compact width, wide width, and Unicode-disabled output.

### Step 3: Add accessible interaction primitives

Add line-oriented `Confirm` and `Select` helpers using injected input/output.
They must show numbered options, a visible default, validation feedback, and
cancel instructions. In a non-interactive environment they return a typed
`ErrNonInteractive` immediately; callers must supply `--yes` or explicit
flags. Secrets are never echoed or accepted through these helpers.

Do not implement raw-mode arrow navigation here. The screenshot's clarity is
achieved by structured choices and progress; line-oriented selection is more
portable and screen-reader friendly. Explicit TUI surfaces may layer richer
navigation separately.

**Verify**: `cd core && go test ./internal/cli/ui -run 'Test(Confirm|Select)' -count=1` → default, alternate choice, invalid retry, EOF/cancel, and non-TTY cases pass without goroutines or timeouts.

### Step 4: Replace the front door with progressive disclosure

Use the new renderer in `printFrontDoor`. In an interactive TTY, show one
compact HELM wordmark, the one-sentence product promise, environment/state
summary if cheaply available, and four actions: Set up, Check risk, Inspect
evidence, More commands. Do not scan the project, touch state, or make network
calls merely to print the front door.

For pipes/non-TTY, print concise plain usage with the same four commands and no
escape sequences or box drawing. Preserve `help --all` as the explicit full
catalog.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run TestFrontDoor -count=1` → TTY and pipe goldens contain the same actions; pipe output has no ANSI; both are side-effect-free.

### Step 5: Migrate doctor as the first complete exemplar

Replace `statusIcon`, raw colors, and byte-length padding with semantic steps
and key/value output. Preserve check logic for this plan; Plan 003 will align
the underlying state model. Render failure suggestions as exact next actions.
JSON output must remain data-only and byte-compatible unless an explicitly
versioned schema change is approved.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'TestDoctor.*(Rendering|JSON|Exit)' -count=1` → PASS/WARN/FAIL words exist in plain output, color is optional, JSON has no chrome, and historical exit semantics remain pinned.

### Step 6: Document the visual and accessibility contract

Extend `docs/guides/cli-io-convention.md` with capability rules, semantic
roles, prompt behavior, width modes, ASCII fallback, and golden-test
requirements. Include examples of interactive, plain, and JSON forms. State
that progress and prompts go to stderr while machine data stays on stdout.

**Verify**: `make docs-truth` → exit 0.

## Test plan

- Unit-test capability detection with injected environment and descriptors.
- Golden-test every renderer in TTY/color and plain modes.
- Test prompts without using a real terminal.
- Compile for Windows and run existing Linux/macOS CI.
- Search emitted plain fixtures for `\x1b`, unstable cursor controls, and
  carriage-return animation; all must be absent.

## Done criteria

- [ ] `NO_COLOR`, `TERM=dumb`, non-TTY, and JSON suppress ANSI.
- [ ] Status is understandable with color and Unicode removed.
- [ ] The front door is compact, branded, side-effect-free, and progressively disclosed.
- [ ] Prompt helpers never prompt in non-interactive mode.
- [ ] Doctor uses the shared renderer and retains its machine contract.
- [ ] No dependency beyond the already-present TTY capability package is added.
- [ ] UI, CLI, docs, gofmt, go vet, and Windows compile checks pass.
- [ ] `plans/README.md` status row is updated.

## STOP conditions

Stop and report if:

- PR #679 lands and provides conflicting terminal capability/style primitives;
- rendering requires changing a signed receipt, EvidencePack, or API schema;
- a proposed visual choice hides or weakens DENY/ESCALATE semantics;
- a new terminal dependency appears necessary for ordinary line output;
- Windows compilation cannot be preserved.

## Maintenance notes

- Review screen-reader/plain snapshots, not just colored screenshots.
- Keep logo and boxes as presentation; state words and next actions are the
  contract.
- Add new primitives only when at least two real command journeys need them.
