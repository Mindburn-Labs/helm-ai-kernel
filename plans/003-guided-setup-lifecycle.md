# Plan 003: Deliver one guided setup, activation, repair, and removal lifecycle

<!-- reconciled status overlay begins -->
> **Reconciled status — PARTIAL:** against source base
> `075bf090240f436b4dad8e458e4a5f35b97aa4b9` on 2026-08-05, a no-argument
> guided project chooser, a project-scoped default with no default quickstart,
> setup preflight/preview/confirmation, and `setup status`, `repair`, and
> `remove` slices are present. Remaining gaps are exact: no transactional
> journal/rollback boundary exists; `onboard` remains an independent state
> writer; and `mcp install` still generates a plugin rather than the promised
> activation flow. This is source-planning reconciliation only, not release,
> deployed, runtime, or production evidence.
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
> `git diff --stat 37b7eabe..HEAD -- core/cmd/helm-ai-kernel/setup_cmd.go core/cmd/helm-ai-kernel/onboard_cmd.go core/cmd/helm-ai-kernel/quickstart_cmd.go core/cmd/helm-ai-kernel/doctor_cmd.go core/cmd/helm-ai-kernel/mcp_cmd.go`
> Also re-query PR #562 and PR #679. If their heads, status, or relevant files
> changed, range-diff them before proceeding.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH
- **Depends on**: `plans/001-cli-safety-and-help.md`, `plans/002-terminal-design-system.md`
- **Category**: migration, dx, security, tests
- **Planned at**: commit `37b7eabe`, 2026-07-31
- **Linear**: [HELM-428](https://linear.app/mindburn/issue/HELM-428)

## Why this matters

First-run behavior is fragmented across `setup`, `onboard`, `quickstart`,
`init`, `connect`, and `mcp install`. A successful `setup status` can be
followed immediately by a failing `doctor` because those commands use
different state roots and trust-root conventions. Setup also mutates keys and
inventory before discovering a missing client binary and starts a blocking
server by default. v0.8.0 needs one truthful lifecycle whose guided TTY flow
and non-interactive flags execute the same plan.

## Current state

- `setup_cmd.go:87-105` is the canonical registry entry but `setup` without
  arguments only prints usage.
- `setup_cmd.go:135-180` mutates the data directory, signing key, inventory,
  draft policy, MCP config, and hook sequentially. There is no single preflight
  or rollback boundary.
- `setup_cmd.go:186-212` starts blocking quickstart unless
  `--no-quickstart` is supplied.
- `setup_cmd.go:296-317` defaults install scope to `user`, the broadest scope,
  and requires `--yes`; no prompt is implemented despite the flag wording.
- `setup_cmd.go:354-365` accepts only `user|project`, although Claude Code has
  local, project, and user scopes.
- `setup_cmd.go:521-545` reports raw booleans (`mcp=true hook=true`) and can
  print an empty Kernel value.
- `setup_cmd.go:570-583` discovers a missing `claude`/`codex` executable only
  after local state has already been written.
- `setup_cmd.go:671-700` and `doctor_cmd.go:229-249` resolve different data and
  key locations. Quickstart defaults to relative `data` and port 7714; doctor
  defaults to relative `data`; server defaults to port 8080; health uses 8081.
- A disposable audit setup reported MCP and hook installed, then doctor failed
  on keypair, database, config, and evidence; its suggestion to run `init` did
  not create the state doctor required.
- `onboard_cmd.go:27-137` writes state and `helm.yaml` immediately, ignores the
  parsed `--yes`, and prints Kubernetes-conflicting `helm ...` next commands.
- `mcp install --client claude-code` generates a plugin directory in cwd; it
  does not install the integration its name promises.
- PR #562 contains useful transaction, recovery, data-dir, lifecycle, and
  security tests but was conflicting and 78 main commits behind at audit time.
  Its full branch touched 95 files and added roughly 13k lines.

## Canonical v0.8.0 journey

Interactive TTY:

```text
helm-ai-kernel setup

HELM
Protect this agent. Keep every decision provable.

[OK] Detected Claude Code and Codex
? Which client should HELM protect?
  1. Claude Code (recommended: detected active)
  2. Codex
? Where should it apply?
  1. This project, private (recommended)
  2. This project, shared
  3. Every project for this user

Planned changes
  MCP server   <path>
  Pre-tool hook <path>
  HELM state   ~/.helm-ai-kernel
? Apply these changes? [Y/n]

[OK] Preflight passed
[OK] MCP boundary configured
[OK] Hook configured
[OK] Client loaded HELM
[OK] First governed decision verified

<completion card with evidence path and one next command>
```

Automation retains explicit form:

```text
helm-ai-kernel setup claude-code --scope local --yes --format json
```

Both paths must use the same lifecycle plan, checks, and result model.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Setup tests | `cd core && go test ./cmd/helm-ai-kernel -run '^TestSetup' -count=1` | exit 0 |
| First-run tests | `cd core && go test ./cmd/helm-ai-kernel -run 'Test(Setup|Onboard|Quickstart|Doctor)' -count=1` | exit 0 |
| CLI suite | `make test-cli` | exit 0 |
| Race-sensitive lifecycle | `cd core && go test -race ./cmd/helm-ai-kernel -run '^TestSetup(Lock|Transaction|Recovery)' -count=1` | exit 0 |
| Cross compile | `make release-binaries` | exit 0, five canonical platform binaries |
| Docs | `make docs-truth` | exit 0 |

## Suggested executor toolkit

- Run `/helm-audit` on the setup and hook paths before editing.
- Use `git range-diff origin/main...origin/helm-178-lifecycle-foundation`
  and targeted `git show` to mine PR #562. Do not merge that branch wholesale.
- Re-check official Claude Code and Codex MCP/hook configuration for the exact
  installed client versions before changing config shapes.

## Scope

**In scope**:

- `core/cmd/helm-ai-kernel/setup_cmd.go`
- `core/cmd/helm-ai-kernel/setup_cmd_test.go`
- `core/cmd/helm-ai-kernel/setup_lifecycle.go` (create)
- `core/cmd/helm-ai-kernel/setup_lifecycle_test.go` (create)
- `core/cmd/helm-ai-kernel/setup_transaction.go` (create)
- `core/cmd/helm-ai-kernel/setup_state.go` (create)
- `core/cmd/helm-ai-kernel/setup_client_claude.go` (create)
- `core/cmd/helm-ai-kernel/setup_client_codex.go` (create)
- OS-specific hook command files only if required by the verified client schema
- `core/cmd/helm-ai-kernel/onboard_cmd.go`, `onboard_cmd_test.go`
- `core/cmd/helm-ai-kernel/quickstart_cmd.go`, `quickstart_cmd_test.go`
- `core/cmd/helm-ai-kernel/mcp_cmd.go` and its install tests
- `core/cmd/helm-ai-kernel/doctor_cmd.go`, `doctor_security_test.go`
- `docs/QUICKSTART.md`, `docs/reference/cli.md`
- `docs/INTEGRATIONS/claude-code.md`, `docs/INTEGRATIONS/codex.md`

**Out of scope**:

- Importing all of PR #562 or its unrelated deployment/store changes.
- Automatically granting Codex workspace trust or Claude project MCP approval.
- Approving tools, policies, or side effects during setup.
- Keeping a server attached to the setup process by default.
- Purging keys, evidence, or receipts during normal integration removal.
- Supporting every editor client interactively in v0.8.0; retain generated
  config output for Cursor/Windsurf/VS Code as an advanced path.

## Git workflow

- Worktree: `helm-ai-kernel-wt-guided-setup` from live `origin/main` after Plans
  001 and 002 merge.
- Branch: `codex/guided-setup-lifecycle`.
- Use small commits: lifecycle model, transaction/preflight, client adapters,
  guided renderer, recovery/removal, aliases/docs.
- In the PR body, record which PR #562 behaviors were ported, superseded, or
  explicitly rejected. Closing #562 occurs only in Plan 005 after merge proof.

## Steps

### Step 1: Define one lifecycle state and support matrix

Model observable states, not optimistic booleans:

- `absent`
- `planned`
- `configured`
- `approval_pending` or `trust_pending`
- `active`
- `degraded`
- `repairable`

A setup result must record client, user-facing scope, native client scope,
workspace, binary identity, state root, config/hook paths, activation checks,
retained data, and next action. Keep secrets and token values out of this
model. Map Claude `local|project|user` explicitly. Map Codex private-project,
shared-project, and user behavior only to officially supported config/trust
mechanisms; do not pretend scopes are identical across clients.

Make `~/.helm-ai-kernel` the default state root, with `HELM_DATA_DIR` and
`--data-dir` as explicit overrides. Setup, quickstart, doctor, server defaults,
and receipt paths must resolve through the same function.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'TestSetup(State|Scope|DataDir)Matrix' -count=1` → every client/scope maps to exact paths and truth states; unsupported combinations fail before writes.

### Step 2: Preflight the complete plan before mutation

Before creating the state directory or key:

- locate and identify the HELM executable;
- locate the selected client executable and confirm its supported commands;
- resolve/canonicalize workspace and all write paths, rejecting symlink escapes;
- parse existing config without modifying it;
- determine trust/approval state;
- check ownership/permissions and potential conflicts;
- compute the exact planned writes, subprocesses, backups, and retained data.

`--dry-run` and the interactive preview render this plan and stop. They must
satisfy Plan 001's no-effects rule. If a client is missing, return one exact
installation/retry hint with no local artifacts left behind.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'TestSetupPreflight' -count=1` → missing client, invalid config, symlink escape, unwritable path, unsupported scope, and conflict cases create zero files and invoke zero subprocesses.

### Step 3: Apply idempotently with rollback and recovery evidence

Port only the smallest proven transaction/recovery pieces from PR #562. Apply
atomic file writes with backups, provision state, install MCP, install hook,
then verify. If any step fails, compensate completed external steps where safe,
restore backed-up files, and return a structured partial-state report with the
exact `setup repair` command. A lifecycle lock must prevent two installers from
racing within the same target.

Do not promise a distributed transaction over client CLIs. The contract is
idempotent plan + bounded rollback + durable recovery facts.

Avoid embedding share-hostile absolute paths in project config when the client
supports a stable command name or environment expansion. Where an absolute path
is required, mark the config private/local and make upgrades rewrite it safely.

**Verify**: `cd core && go test -race ./cmd/helm-ai-kernel -run '^TestSetup(Transaction|Rollback|Recovery|Concurrent)' -count=1` → fault injection after every step leaves either the prior state restored or a deterministic repairable journal; rerun converges to active.

### Step 4: Build the guided TTY flow over the same plan

Use Plan 002's `Select`, `Confirm`, steps, and completion card. `setup` with no
arguments starts the wizard only when interactive; under a pipe it prints
concise help and exits without prompting. Auto-detect installed clients and
existing HELM configuration, recommend the narrowest private project scope,
show every path before confirmation, then stream stable step states.

Do not use a giant logo after first run, animation, or simulated progress. A
step appears only when its underlying operation starts and reaches OK only when
verified. Cancel at any prompt with no effects.

Keep `setup <client> --scope ... --yes --format json` for CI and scripts. It
must execute the identical lifecycle plan without prompts or ANSI.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'TestSetup(Guided|NonInteractive)' -count=1` → scripted stdin goldens cover detected clients, choice, confirmation, cancellation, defaults, no-color, pipe rejection, and JSON parity.

### Step 5: Verify real activation and produce a first proof

After configuration, verify more than file presence:

- `claude mcp get helm-ai-kernel-governance` or equivalent official client
  inspection reports loaded/healthy, or truthfully reports approval pending;
- `codex mcp get helm-ai-kernel-governance` in the selected configuration
  context reports the server, or status reports trust pending;
- hook config parses and selects the OS-specific command where supported;
- a bounded local HELM self-check produces and verifies one non-destructive
  decision receipt without starting a long-running server.

Never self-approve project configuration or workspace trust. Pending is a valid
completion state only when the card says it is pending and prints the exact
operator action.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'TestSetup(Activation|FirstProof|TrustPending|ApprovalPending)' -count=1` → installed-but-inert never reports active; successful active setup points to a verified receipt.

### Step 6: Make status, repair, and removal complete the lifecycle

Implement `setup status`, `setup repair`, and `setup remove` over the same
state/client adapters. Status reports configured, loaded, hook, key, store,
receipt, and pending states. Repair recomputes and applies only missing/drifted
steps after preview/confirmation. Remove previews exact integration edits,
requires confirmation or `--yes`, removes only HELM-owned entries, and states
that keys/evidence/state are retained. A separately named guarded purge can be
deferred; do not hide it inside remove.

Doctor must consume this state resolver even if its output migration completes
in Plan 004.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'TestSetup(Status|Repair|Remove)' -count=1` → drift cases are truthful, repair is idempotent, removal preserves unrelated config and local evidence, and a second remove is a no-op success.

### Step 7: Collapse competing first-run fronts without abrupt breakage

- Route `onboard` to guided setup with one deprecation warning on TTY/stderr;
  remove its independent state writer and all `helm ...` next commands.
- Keep `quickstart` as an advanced explicit local server/proof command; setup
  no longer starts it by default.
- Rename the behavior behind `mcp install` to an accurate plugin/package build
  command; keep the old name as a deprecation alias for one minor release.
- Keep `init` only for project scaffold semantics and ensure its help explains
  that distinction.
- Point root help and docs only to `setup` as the activation front door.

**Verify**: `make test-cli && make docs-truth` → exit 0; a literal search finds no canonical quickstart instructions using bare `helm`, no default blocking setup server, and no docs claiming `mcp install` performs activation.

## Test plan

- Matrix: Claude local/project/user; Codex project/user and trust-pending;
  macOS/Linux/Windows command shapes; TTY/plain/JSON.
- Fault injection before and after each mutation/subprocess.
- Upgrade tests from old binary path/state root and re-run idempotency.
- Malformed/unrelated client config preservation tests.
- Removal retention and no-secret-output tests.
- Exact client CLI tests use fakes in unit tests; one opt-in smoke may use
  installed `claude`/`codex` without modifying real user config.

## Done criteria

- [ ] `helm-ai-kernel setup` is a guided, cancellable TTY journey.
- [ ] Narrow project-private scope is recommended; user/global is explicit.
- [ ] Preview and preflight write nothing.
- [ ] Failed apply rolls back or returns a deterministic repair path.
- [ ] Active means client-loaded plus bounded HELM proof, not file-present.
- [ ] Setup/status/repair/remove/doctor resolve the same state root and model.
- [ ] Setup does not start a blocking server by default.
- [ ] Legacy fronts route/deprecate without silently changing authority.
- [ ] Cross-platform hook commands are verified against official schemas.
- [ ] Focused, CLI, race, cross-compile, and docs gates pass.
- [ ] `plans/README.md` status row is updated.

## STOP conditions

Stop and report if:

- official client behavior cannot verify activation without mutating approval or trust;
- a client schema changed since the audit and current docs/source do not agree;
- transaction recovery requires importing unrelated PR #562 authority/store work;
- a proposed repair would overwrite config entries HELM does not own;
- shared project config requires a machine-specific absolute secret/key path;
- any flow would self-grant approval, trust, or policy authority.

## Maintenance notes

- Review truth words carefully: configured, pending, active, and verified are
  deliberately different states.
- Client adapters should stay small; the lifecycle owns ordering and rollback.
- Update the support matrix whenever an upstream client scope/hook contract changes.
