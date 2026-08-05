# Plan 004: Unify command discovery, diagnostics, receipts, and automation contracts

<!-- reconciled status overlay begins -->
> **Reconciled status — PARTIAL:** against source base
> `075bf090240f436b4dad8e458e4a5f35b97aa4b9` on 2026-08-05, safe
> dispatcher help, a command catalog/completion slice, and targeted
> discoverability tests are present. Remaining gaps are exact: registry metadata
> still lacks groups, examples, deprecation/destructive, and nested-command
> fields; full help remains alphabetic; unknown commands lack suggestions;
> global output/version and the explicit 126 exit contract remain incomplete;
> and no generated CLI-reference or example smoke script exists. This is
> source-planning reconciliation only, not release, deployed, runtime, or
> production evidence.
>
> **Historical plan body:** the executor instructions, audit facts, and
> checkboxes below were authored against `37b7eabe` on 2026-07-31. They are
> retained for provenance and are not current-state or release evidence.
<!-- reconciled status overlay ends -->

> **Executor instructions**: This is a multi-commit migration plan. Complete
> each wave and its verification before starting the next. Do not change signed
> payloads or domain behavior merely to normalize presentation. If a STOP
> condition occurs, stop and report. Update this plan's row in
> `plans/README.md` when done.
>
> **Drift check (run first)**:
> `git diff --stat 37b7eabe..HEAD -- core/cmd/helm-ai-kernel/registry.go core/cmd/helm-ai-kernel/cli_support.go core/cmd/helm-ai-kernel/main.go core/internal/cli/ui docs/reference/cli.md docs/guides/cli-io-convention.md`
> Re-run the command/help inventory before implementation; counts below are
> audit evidence, not assumptions to preserve.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: MED
- **Depends on**: Plans 001, 002, and 003
- **Category**: dx, migration, docs, tests
- **Planned at**: commit `37b7eabe`, 2026-07-31
- **Linear**: [HELM-429](https://linear.app/mindburn/issue/HELM-429)

## Why this matters

The CLI exposes 66 top-level commands and 171 `flag.FlagSet` parsers in one
alphabetical wall. Nine command files use the shared I/O convention, leaving
most help, JSON, errors, streams, and exits command-specific. Evidence is split
among `receipts`, `workstation`, `verify`, `evidence`, `mcp receipts`, and
boundary records. A polished front door cannot compensate for a command model
users cannot predict or scripts cannot trust.

## Current state

- `core/cmd/helm-ai-kernel/registry.go:10-16` stores only name, aliases, one
  usage string, and handler. It has no group, examples, deprecation, or nested
  command metadata.
- `registry.go:42-63` alphabetizes every canonical command into a flat list.
- `main.go:74-131` mixes registry and legacy dispatch; `trust`, `run`, and
  other paths have overlapping/dead routing.
- `main.go:102-108` renders `--version` as styled multi-line human output.
- `docs/guides/cli-io-convention.md:82-101` records only nine migrated
  commands and explicitly recommends waves of about ten.
- `core/internal/cli/ui/ui.go:31-42` documents 0/1/2 and sanitizes errors above
  125, while `workstation_m3_cmd.go:58,65` intentionally returns 126 for an
  enforcement denial. The public contract is incomplete.
- `docs/reference/cli.md:13-30` mixes first proof and setup; its EvidencePack
  example differs from `docs/QUICKSTART.md`, and it recommends
  `verify --help`, which exited 2 during the audit.
- Exact warm execution was already fast enough: about 18.5 ms for `version`,
  31.4 ms for the root, and 24.9 ms for full help. Do not justify a framework
  rewrite as a performance fix.
- The exact raw `go build` reported v0.5.10 because
  `buildinfo.go:5-15` duplicates a stale fallback while `VERSION` is 0.7.5.

## Target command model

Root help shows common outcomes, not implementation nouns:

```text
Get started
  setup       Protect Claude Code or Codex
  scan        Find ungoverned agent risk
  doctor      Check and repair HELM activation

Use HELM
  receipts    Inspect and verify decisions
  mcp         Govern MCP tools and approvals
  launch      Run or stop a governed app

Run `helm-ai-kernel help --all` for advanced commands.
```

Full help groups commands by user intent: Get started, Govern, Evidence,
Operate, Build/Integrate, and Advanced. Frequently used commands precede rare
commands within a group; they are not alphabetized into one wall.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| CLI tests | `make test-cli` | exit 0 |
| Help matrix | `cd core && go test ./cmd/helm-ai-kernel -run 'Test(Help|Completion|CommandCatalog)' -count=1` | exit 0 |
| I/O goldens | `cd core && go test ./cmd/helm-ai-kernel -run 'TestCLIUI' -count=1` | exit 0 |
| UI tests | `cd core && go test ./internal/cli/ui -count=1` | exit 0 |
| Docs | `make docs-truth docs-coverage` | exit 0 |
| Lint | `make lint` | exit 0 |
| Release smoke | `make build && bash scripts/ci/release_smoke.sh` | exit 0 |

## Scope

**In scope**:

- `core/cmd/helm-ai-kernel/registry.go`, `registry_test.go` (create)
- `core/cmd/helm-ai-kernel/command_catalog.go` (create)
- `core/cmd/helm-ai-kernel/command_catalog_test.go` (create)
- `core/cmd/helm-ai-kernel/cli_support.go`, `main.go`, `main_test.go`
- `core/cmd/helm-ai-kernel/completion_cmd.go` and tests (create)
- Command registration/help sites under `core/cmd/helm-ai-kernel/*_cmd.go`
- `core/cmd/helm-ai-kernel/doctor_cmd.go` and tests
- `core/cmd/helm-ai-kernel/receipts_cmd.go`, `workstation_cmd.go`,
  `verify_cmd.go`, `evidence_cmd.go`, `mcp_cmd.go`, and their tests
- `core/cmd/helm-ai-kernel/buildinfo.go`
- `core/internal/cli/ui/ui.go` and tests
- `docs/reference/cli.md`, `docs/QUICKSTART.md`, README CLI examples
- `docs/guides/cli-io-convention.md`
- a small doc-generation/check script under `scripts/ci/`
- `Makefile` and CI workflow entries needed to run the checks

**Out of scope**:

- Renaming signed domain concepts, receipt fields, policy actions, or API routes.
- Removing compatibility commands in v0.8.0; deprecate and route first.
- YAML output, user-defined templates, pager integration, telemetry, or a shell
  REPL. Text and JSON cover the release requirements.
- Replacing Go `flag` or the registry with Cobra.
- Making repair automatic from `doctor`; it points to Plan 003's explicit
  `setup repair` path.

## Git workflow

- Worktree: `helm-ai-kernel-wt-cli-contracts` from live `origin/main` after
  Plans 001–003 merge.
- Branch: `codex/cli-information-architecture`.
- Keep each I/O migration wave to about ten command surfaces, matching the
  repository's documented fan-out rule. Each wave gets its own commit and
  exact golden tests.
- Before modifying verdict text, range-diff live PR #684 and preserve its
  reason/evidence/remediation contract.

## Steps

### Step 1: Turn the registry into the command source of truth

Extend command metadata only as far as required: canonical path, group,
summary, usage line, examples, aliases, hidden/deprecated state, destructive
marker, and optional nested specs/help renderer. Registration must reject
duplicates and the catalog test must fail if a public command lacks group,
summary, usage, or help.

Keep one registry; do not create a separate hand-maintained docs taxonomy.
Where handlers already declare nested subcommands, move only their descriptive
metadata into the shared spec and leave execution in the existing handler.

Group all current commands by user intent. Root help exposes the six common
commands shown above; `help --all` exposes every non-hidden command in grouped
order. `help <command> [subcommand]`, `<path> help`, `<path> -h`, and `<path>
--help` resolve to the same renderer and exit 0 without calling handlers.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'Test(CommandCatalog|HelpPath|HelpMatrix)' -count=1` → every public path has metadata/help, aliases resolve to canonical paths, deprecated commands are marked, and help has zero effects.

### Step 2: Add suggestions, examples, and progressive error recovery

For unknown commands/subcommands, compute a bounded edit-distance suggestion
from the applicable catalog using a small local function. Print at most three
matches and one exact help command. Error shape is:

```text
Error: unknown command "scna"
  Did you mean: scan
  Run: helm-ai-kernel scan --help
```

Usage errors show the failed input, the constraint, and next action; operational
errors explain what failed and how to inspect/retry. Preserve PR #684's
`outcome -> reason -> evidence -> approve/recover` verdict exemplar.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'Test(Unknown|Suggestion|ActionableError)' -count=1` → typo, ambiguity, nested typo, and no-close-match goldens pass in text and JSON error modes.

### Step 3: Generate shell completion from command metadata

Add `completion bash|zsh|fish|powershell`. Generate command paths, aliases,
flags, enum values, and descriptions from the registry. Never execute a
command to discover its flags. Completion output goes to stdout with no ANSI;
install instructions go to help/stderr.

Provide deterministic snapshots and syntax smoke checks using the shells
available in CI. The generator must omit hidden commands, mark deprecated
aliases, and never complete secret/token values.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'TestCompletion' -count=1` → deterministic snapshots for all four shells; `helm-ai-kernel completion zsh` contains setup/receipts/launch paths and no color/control sequences.

### Step 4: Normalize global output and exit behavior

Parse a small global option set consistently before dispatch:

- `--format text|json` with legacy `--json` aliases where already public;
- `--color auto|always|never` for human output only;
- `--quiet` for non-result chrome;
- `--non-interactive`, automatically true when input is not a TTY.

Apply the existing stdout-data/stderr-chrome convention. Structured JSON
results include a versioned envelope only where a command does not already have
a public pinned schema; never silently wrap signed/protocol JSON. JSON errors
remain one document on stderr. Document and preserve exits 0 success, 1
operational/negative verification, 2 usage, and the intentional 126
fail-closed execution denial. Update `ui.ExitCode` so 126 is explicit rather
than an out-of-range accident; do not generalize arbitrary shell-reserved codes.

Make `--version` one plain line suitable for scripts. `version --format json`
returns version, commit, build time, and schema versions. Replace the duplicated
v0.5.10 fallback with source-controlled/generated version truth so raw developer
builds cannot claim an obsolete release.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel ./internal/cli/ui -run 'Test(Format|Streams|Exit|Version)' -count=1` → pipe-safe goldens, explicit 126, no secret/chrome leakage, and `VERSION` parity pass.

### Step 5: Complete I/O migration in small waves

Inventory live commands again and migrate leaf-first, no more than roughly ten
surfaces per commit:

1. **First-run**: setup, doctor, scan, init, connect, login, quickstart.
2. **Evidence**: receipts, evidence, verify, audit, report, log, replay, rollup,
   traces, export.
3. **Governance**: boundary, approvals, authz, budget, policy, trust, freeze,
   unfreeze, counterfactual, bundle.
4. **Runtime**: mcp, hook, proxy, sandbox, launch, app, run, up, teardown,
   incident, health.
5. **Advanced remainder**: every catalog entry not covered above.

For each surface: map `flag.ErrHelp` to success, reject stray positionals,
adopt shared errors/format, move chrome to stderr, retain legacy JSON alias,
and add a golden. Do not batch domain changes with presentation migration.

**Verify after each wave**: `make test-cli` → exit 0; catalog test reports no
unmigrated public command; plain/JSON stream goldens pass.

### Step 6: Consolidate evidence navigation behind receipts

Make `receipts` the discoverable evidence front:

- `receipts list` / `tail`
- `receipts show <id-or-path>`
- `receipts verify <id-or-path>`
- `receipts export <id-or-path> --out <path>`

Reuse existing workstation, EvidencePack, boundary, and verifier functions;
do not duplicate verification logic. Preserve `workstation verify-decision`,
`verify`, `evidence verify`, and `mcp receipts` as compatibility routes that
point to the canonical command in help/deprecation output when semantics match.
When semantics differ, keep the specialized command and state why.

A human result uses the PR #684 pattern: verdict, reason code, signer/trust,
evidence path/hash, and exact next action. JSON preserves signed objects and
never implies trusted signer status from self-contained signature validity.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'TestReceipts' -count=1` → canonical and compatibility paths return equivalent domain results and exits for valid, invalid, untrusted, missing, and tampered fixtures.

### Step 7: Align doctor with the canonical setup state

Doctor reads Plan 003's lifecycle state and reports four layers separately:
binary/version, state/key/store, client MCP/hook/trust/approval, and first-proof
evidence. Use the actual configured port/state root; never test 8080/8081 when
the selected setup uses 7714. Every failed check points to `setup repair`, an
approval/trust action, or an exact inspect command that can heal it.

`doctor --format json` distinguishes `healthy`, `degraded`, `pending`, and
`failed`; warnings do not masquerade as hard failures. Pin exit semantics in
docs and tests.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'TestDoctor' -count=1` → fresh, configured, trust-pending, active, drifted, corrupt, and removed-but-data-retained fixtures agree with `setup status`.

### Step 8: Generate and execute the CLI reference

Generate the command catalog portion of `docs/reference/cli.md` from registry
metadata and keep narrative journeys hand-authored. CI fails when generated
output drifts. Extract every fenced `helm-ai-kernel` example into a smoke run
that permits explicit placeholders but fails on unknown commands/flags or
nonzero help.

Unify the EvidencePack path, install command, setup scope examples, and receipt
journey across README, Quickstart, integration guides, and reference. Advanced
docs can expose all 66 commands; first-run docs show one path.

**Verify**: `make docs-truth docs-coverage && bash scripts/ci/cli_docs_smoke.sh` → exit 0 with no generated diff and every non-operational example parses.

## Test plan

- Registry/catalog completeness and duplicate tests.
- Every command path: `help`, `-h`, `--help`, invalid flag, extra positional,
  text and JSON error.
- TTY/plain/no-color/JSON goldens from Plan 002.
- Shell completion snapshots and syntax checks.
- Receipts equivalence tests using existing signed/tampered fixtures.
- Doctor/setup state-matrix parity.
- Raw developer build and release build version parity.
- Warm startup budget: root/help/version p95 must not regress by more than 25%
  from the recorded audit on the same runner; report rather than guess at size.

## Done criteria

- [ ] Root help shows six common outcomes; full help is grouped and complete.
- [ ] Every public command/subcommand has side-effect-free help and metadata.
- [ ] Typos produce bounded actionable suggestions.
- [ ] Bash, zsh, fish, and PowerShell completion derive from the registry.
- [ ] All public surfaces follow text/JSON, stdout/stderr, and documented exits.
- [ ] `--version` and raw/release builds report current source truth.
- [ ] Receipts is the canonical evidence navigation front without verifier duplication.
- [ ] Doctor and setup status agree for every lifecycle fixture.
- [ ] CLI docs are generated/checked and examples smoke successfully.
- [ ] CLI, UI, docs, lint, release-smoke, and performance gates pass.
- [ ] `plans/README.md` status row is updated.

## STOP conditions

Stop and report if:

- normalization requires changing a signed/protocol JSON payload;
- two apparently duplicate commands have materially different trust semantics;
- PR #684 or #679 lands with conflicting public command/output contracts;
- a compatibility alias cannot preserve exit/output behavior safely;
- generated completion would require evaluating a command or reading secrets;
- a migration wave exceeds the planned size because domain refactoring is also required.

## Maintenance notes

- The catalog is product information architecture; review names and groups as
  carefully as code.
- Keep common commands first. OpenAI Codex's command source explicitly orders
  frequent actions ahead of rare ones; alphabetic order is not a UX goal.
- Preserve deterministic noninteractive behavior even as guided TTY flows improve.
