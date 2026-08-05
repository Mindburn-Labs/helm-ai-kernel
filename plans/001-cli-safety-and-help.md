# Plan 001: Make help, preview, reset, and teardown side-effect-safe

<!-- reconciled status overlay begins -->
> **Reconciled status — DONE (source/test safety scope only):** verified against
> source base `075bf090240f436b4dad8e458e4a5f35b97aa4b9` on 2026-08-05.
> Dispatcher help interception and duplicate registration rejection, dry-run
> ordering, guarded quickstart reset, `--cascade` validation before deletion,
> the compatibility teardown path, and the CLI safety tests are present. This
> is source/test evidence only; it is not release, publication, deployment,
> runtime, rollback, production, or customer evidence.
>
> **Historical plan body:** the executor instructions, audit facts, and
> checkboxes below were authored against `37b7eabe` on 2026-07-31. They are
> retained for provenance and are not current-state or release evidence.
<!-- reconciled status overlay ends -->

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If a STOP condition occurs, stop and report; do not improvise.
> When done, update this plan's row in `plans/README.md`.
>
> **Drift check (run first)**:
> `git diff --stat 37b7eabe..HEAD -- core/cmd/helm-ai-kernel/registry.go core/cmd/helm-ai-kernel/main.go core/cmd/helm-ai-kernel/quickstart_cmd.go core/cmd/helm-ai-kernel/launch_cmd.go core/cmd/helm-ai-kernel/teardown_cmd.go`
> If any in-scope file changed, compare the current-state excerpts below with
> live code. A semantic mismatch is a STOP condition.

## Status

- **Priority**: P1 — v0.8.0 release blocker
- **Effort**: M
- **Risk**: HIGH
- **Depends on**: none
- **Category**: security, bug, tests
- **Planned at**: commit `37b7eabe`, 2026-07-31
- **Linear**: [HELM-426](https://linear.app/mindburn/issue/HELM-426)

## Why this matters

The current CLI violates the fundamental rule that help and preview are safe.
`init --help` creates a project named `--help`, several help calls write
boundary files, `health --help` makes a network call, and `quickstart
--dry-run` creates a database, keys, policy, and a secret token. More severely,
`launch delete` reaches provider deletion even when `--cascade` is absent.
These behaviors can cause loss or surprise before visual polish is relevant.

## Current state

- `core/cmd/helm-ai-kernel/main.go:68-77` dispatches directly to a handler
  before interpreting help.
- `core/cmd/helm-ai-kernel/registry.go:29-35` calls `RunFn` without a help
  guard. `Register` also silently overwrites duplicate names and aliases.
- `core/cmd/helm-ai-kernel/quickstart_cmd.go:50-59` calls
  `prepareQuickstart` before the dry-run return.
- `quickstart_cmd.go:167-194` may call `os.RemoveAll`, create directories,
  initialize SQLite and keys, write policy files, and generate a bootstrap
  token.
- `core/cmd/helm-ai-kernel/launch_cmd.go:687-722` parses `--cascade` but never
  rejects `cascade == false`; it calls `deleteCloudResourcesForRun` first.
- `core/cmd/helm-ai-kernel/teardown_cmd.go:12-17` forwards straight to that
  delete path.
- `quickstart_local_first_run_test.go:17` currently expects dry-run to prepare
  local state; that test pins the bug and must be replaced.
- Audit matrix at `37b7eabe`: of 66 top-level `--help` calls, 21 exited 0,
  40 exited 2, 5 attempted operations and exited 1, and 6 wrote files.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Focused tests | `cd core && go test ./cmd/helm-ai-kernel -run 'Test(Help|Quickstart|LaunchDelete|Teardown)' -count=1` | exit 0 |
| CLI suite | `make test-cli` | exit 0 |
| Formatting | `cd core && test -z "$(gofmt -l cmd/helm-ai-kernel)"` | exit 0, no paths |
| Static checks | `cd core && go vet ./cmd/helm-ai-kernel/...` | exit 0 |

## Scope

**In scope**:

- `core/cmd/helm-ai-kernel/registry.go`
- `core/cmd/helm-ai-kernel/main.go`
- `core/cmd/helm-ai-kernel/quickstart_cmd.go`
- `core/cmd/helm-ai-kernel/launch_cmd.go`
- `core/cmd/helm-ai-kernel/teardown_cmd.go`
- `core/cmd/helm-ai-kernel/main_test.go`
- `core/cmd/helm-ai-kernel/quickstart_cmd_test.go`
- `core/cmd/helm-ai-kernel/quickstart_local_first_run_test.go`
- `core/cmd/helm-ai-kernel/launch_cmd_test.go`
- `core/cmd/helm-ai-kernel/cli_help_safety_test.go` (create)

**Out of scope**:

- Redesigning command help or visual styling; Plans 002 and 004 own that.
- Changing Launchpad provider APIs, receipt schemas, or cloud teardown order
  after authority has been validated.
- Deleting existing state to make tests pass.
- Merging PR #679, #684, or #715 as part of this patch.

## Git workflow

- Create `helm-ai-kernel-wt-cli-safety-help` from live `origin/main` using the
  repository worktree helper.
- Branch: `codex/cli-safety-help`.
- Use conventional commits; suggested commits are
  `fix(cli): make help and preview side-effect free` and
  `fix(launch): require explicit teardown authority`.
- Do not push or open a PR unless the operator instructed it; when instructed,
  run `/helm-pr-preflight` and the source-owned permit path.

## Steps

### Step 1: Intercept help before command execution

Extend `Subcommand` with an optional help renderer and add a dispatcher-level
check for `-h`, `--help`, and `help`. The check must run before `RunFn`. Until
Plan 004 supplies rich nested metadata, the fallback renderer should print the
canonical command name, `Usage`, and `helm-ai-kernel help --all`; it must never
invoke the command handler. Treat help as success and write it to stdout.

Do not rely on `flag.ErrHelp`: handlers that do not use `flag` are the paths
that currently mutate state. Reject duplicate command names and aliases during
registration instead of silently overwriting them.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'TestHelpMatrix|TestRegisterRejectsDuplicate' -count=1` → all 66 canonical commands return 0 for `-h` and `--help`, stdout is non-empty, stderr is empty, and fixture directories/network/provider spies record zero effects.

### Step 2: Make dry-run a pure planning operation

Split quickstart planning from application. Planning may normalize arguments,
derive the URL and policy destination, and describe planned actions. It must
not create directories, open SQLite, generate keys or session material, write
policy/reference packs, set environment variables, or expose a bootstrap
token. Call mutation-only preparation after the dry-run return.

Change the dry-run JSON schema to include `operation: "preview"`, the resolved
paths, and `planned_actions`; omit `bootstrap_token` entirely. Keep the real
runtime token in the explicit live startup path only.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'TestQuickstartDryRun' -count=1` → exit 0, valid JSON, target data directory absent, environment unchanged, and output contains no token field or token-like value.

### Step 3: Guard reset targets before deletion

Add the smallest shared guard next to `prepareQuickstart`:

- canonicalize the absolute target and resolve existing symlinks;
- reject empty, `.`, filesystem root, current working directory, home, or any
  ancestor of home/current workspace;
- require both `--reset` and `--yes` for non-interactive deletion;
- require a HELM-owned marker created during successful quickstart
  initialization; legacy directories without the marker must be preserved and
  reported with a recovery hint;
- validate before `os.RemoveAll` and surface the exact resolved target.

Do not create a general deletion framework. This guard owns one destructive
path and can be promoted later only if another path proves identical needs.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'TestQuickstartReset' -count=1` → table cases prove root, home, cwd, parent, symlink escape, unmarked target, and missing `--yes` are untouched; a marked temp target is reset.

### Step 4: Enforce teardown authority before all reads and provider calls

Parse and validate `launch delete` arguments before constructing the store or
loading a run. Require exactly one non-flag launch ID and `--cascade`. Handle
help in the dispatcher. Only after validation may the function read state or
call `deleteCloudResourcesForRun`. Keep `teardown` as a compatibility alias
that goes through the same validated path.

Inject or reuse a provider-delete seam in tests; do not hit a live provider.
Pin that missing `--cascade`, unknown flags, extra positionals, help, or a blank
ID produces zero store writes and zero provider calls.

**Verify**: `cd core && go test ./cmd/helm-ai-kernel -run 'Test(LaunchDelete|Teardown)' -count=1` → destructive negative cases exit 2 with no effects; authorized fixture deletion still emits its existing receipt/evidence behavior.

### Step 5: Add the release-blocking side-effect matrix

Create one table-driven test that enumerates canonical registered commands.
Run help in a fresh temporary cwd with isolated HOME/data variables and
network/provider seams. Snapshot the directory before and after. This is the
permanent guard against future command-local help regressions.

Also test the historically harmful commands explicitly: `init`, `health`,
`launch`, `teardown`, `up`, `coverage`, `approvals`, `authz`, `budget`,
`boundary`, and `traces`.

**Verify**: `make test-cli` → exit 0 and the matrix reports no writes, network calls, subprocesses, or provider calls.

## Test plan

- Replace `TestQuickstartDryRunJSONPreparesLocalOSSFirstRun` with tests that
  prove preview purity and move preparation assertions to a live-preparation
  unit test.
- Add provider-spy tests around `runLaunchDelete` for absent authority.
- Add registry duplicate and help interception tests.
- Run the full CLI package twice (`-count=2`) to catch leaked process-global
  environment or registry state.

## Done criteria

- [ ] All 66 top-level commands return 0 for `-h` and `--help`.
- [ ] Help creates no files and starts no network, subprocess, or provider work.
- [ ] Quickstart dry-run leaves an absent target absent and emits no secret.
- [ ] Unsafe/unmarked reset targets are never passed to `os.RemoveAll`.
- [ ] Teardown cannot reach store/provider mutation without `--cascade`.
- [ ] `make test-cli`, focused tests, gofmt, and go vet pass.
- [ ] `git diff --name-only` contains only in-scope files and the plan index.
- [ ] `plans/README.md` status row is updated.

## STOP conditions

Stop and report if:

- protected-path policy requires a different explicit teardown authority than
  `--cascade`; do not invent or weaken it;
- an existing release consumer depends on bootstrap tokens in dry-run output;
- provider calls cannot be replaced with a deterministic test seam;
- the safe reset target cannot be distinguished from arbitrary user data;
- any in-scope behavior has materially changed since `37b7eabe`.

## Maintenance notes

- Reviewers should inspect ordering: parse/help/authority validation must occur
  before all reads and writes, not merely before the final delete call.
- Plan 004 may replace fallback help text, but must preserve this no-handler
  execution property.
- Keep the matrix fast and hermetic so it can block every PR.
