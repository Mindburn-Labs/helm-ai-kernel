# Plan 005: Reconcile the estate and qualify, publish, deploy, and prove v0.8.0

<!-- reconciled status overlay begins -->
> **Reconciled status — ACTIVE / BLOCKED:** against source base
> `075bf090240f436b4dad8e458e4a5f35b97aa4b9` on 2026-08-05. This plan is
> blocked pending source-owned release authority for an exact head, a current
> estate disposition ledger with authority for every action, and authorized
> live deployment, runtime, and rollback evidence. No v0.8.0 release,
> publication, deployment, runtime, production, or customer claim follows from
> this plan or its historical snapshot.
>
> **Historical plan body:** the executor instructions, audit facts, and
> checkboxes below were authored against `37b7eabe` on 2026-07-31. They are
> retained for provenance and are not current-state or release evidence.
<!-- reconciled status overlay ends -->

> **Executor instructions**: This plan is both engineering and release
> operations. Re-query every remote fact immediately before acting. Never merge,
> close, delete, publish, deploy, or claim completion from the 2026-07-31
> snapshot alone. Run every gate and retain its URL/digest/evidence. Stop on any
> failed authority or production gate. Update this plan's row in
> `plans/README.md` only after all done criteria hold.
>
> **Drift check (run first)**:
> `git diff --stat 37b7eabe..HEAD -- VERSION CHANGELOG.md RELEASE.md release/ Makefile .github/workflows/ docs/ README.md`
> Also run `git fetch --all --prune`, re-enumerate PRs/branches/worktrees/tags,
> and replace every snapshot count in the working ledger with live values.

## Status

- **Priority**: P1 — release gate
- **Effort**: L
- **Risk**: HIGH
- **Depends on**: Plans 001–004 complete and merged
- **Category**: migration, tests, docs, direction
- **Planned at**: commit `37b7eabe`, 2026-07-31
- **Linear**: [HELM-430](https://linear.app/mindburn/issue/HELM-430), [HELM-230](https://linear.app/mindburn/issue/HELM-230)

## Why this matters

The existing “v0.7.3 → v0.8.0” train is obsolete: v0.7.5 is the latest public
release and the CLI has since accumulated unmerged safety, setup, verdict, TUI,
and evidence work. The repository snapshot contained 47 open PRs, 136 non-main
remote branches, 62 local branches, and 58 worktrees. v0.7.5 also proves that a
GitHub Release object is not an end-to-end finish: its release workflow failed
post-release because Artifact Hub remained on 0.7.4 and three live docs pages
did not contain the 0.7.5 SDK truth. v0.8.0 is complete only when source,
authority, artifacts, registries, docs, deployment, runtime proof, and estate
cleanup all agree.

## Current state

Snapshot time: 2026-07-31. Re-query before use.

- `main == origin/main == 37b7eabe39d96de04c8b7dd445c21c84f2dc9619`.
- Main worktree has two user-owned untracked archives:
  `core/social-narrator-skill.tar.gz` and `core/social-narrator.tar.gz`.
  They are not release inputs and must be preserved.
- Latest tag/release: v0.7.5, tag commit `71b7e73a58d7` in the release run.
- v0.7.5 release workflow run `30031231555` concluded failure.
- Its post-release drift failures were Artifact Hub chart 0.7.4 and missing
  0.7.5 SDK strings on live docs pages `/developer-journey`, `/sdks`, and
  `/examples`. GitHub assets, GHCR images/chart, SDK registries, Homebrew, and
  Go proxy were reported current in that run.
- `release/README.md` names v0.7.5 as target, but the in-tree VEX list visible at
  audit time stopped at `release/vex/v0.7.3.openvex.json`; resolve live drift
  rather than copying an old artifact.
- PR #684 was clean/mergeable with successful release permit.
- PR #679 was mergeable with a failed release permit.
- PR #562 was conflicting/stale.
- PR #715 had kernel, contract-drift, and permit failures.
- Focused current-main tests passed:
  `go test ./cmd/helm-ai-kernel ./internal/cli/ui -count=1`.

## What “deployed” means

HELM Kernel is a headless product and library. Release deployment has distinct
proof states:

1. signed v0.8.0 CLI/SDK/chart/container artifacts are public and installable;
2. the canonical docs site renders v0.8.0 journeys;
3. every production GitOps consumer that is authorized to run the Kernel is
   pinned to the v0.8.0 digest and reconciled;
4. staging and production smoke produce source-owned receipts/EvidencePacks;
5. rollback to the prior pinned digest is rehearsed or evidenced.

If topology/source truth identifies no production runtime consumer for the
public Kernel image, do not invent one. In that case artifact publication is
the Kernel deployment, while broader HELM production deployment remains a
separate explicit blocker/claim boundary.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Refresh | `git fetch --all --prune && gh pr list --state open --limit 250` | exit 0, live estate |
| Merge quality | `make quality-merge` | exit 0 |
| Release quality | `make quality-release` | exit 0 |
| Release readiness | `make release-readiness` | exit 0 |
| Assets | `make release-assets` | exit 0, complete v0.8.0 staged set |
| Local version drift | `make version-drift` | exit 0 |
| Docs | `make docs-coverage docs-truth` | exit 0 |
| Published drift | `make version-drift-published` | exit 0 after publication |
| Worktrees | `git worktree list --porcelain` | only canonical worktree at finish |
| Branches | `git branch -a` | local `main` and remote `origin/main` only at finish |

## Suggested executor toolkit

- Use `/helm-audit` before each protected-path tranche and
  `/helm-pr-preflight` on every merge candidate.
- Use the mandatory Linear integration to keep the v0.8.0 project and issue
  dispositions synchronized with evidence.
- Use source-owned release-permit and exact-head approval gates. A label,
  comment, branch name, or local test is not merge authority.
- Use the approved GitOps and deployment skills only after release authority is
  proven; release permit alone never authorizes deployment.

## Scope

**In-repo scope**:

- `VERSION`, `CHANGELOG.md`, `RELEASE.md`, `release/`,
  `release/version-surfaces.yaml`
- `Makefile`, `scripts/release/`, `scripts/ci/`
- `.github/workflows/release.yml` and SDK publisher workflows
- `README.md`, `docs/QUICKSTART.md`, `docs/PUBLISHING.md`,
  `docs/VERIFICATION.md`, `docs/RELEASE_SECURITY.md`, release-indexed docs
- CLI/build changes from Plans 001–004
- `plans/README.md`

**Cross-repo operational scope, only where source truth assigns ownership**:

- `homebrew-tap` formula publication
- the canonical HELM docs application resolved from current topology
- `gitops-apps` / `gitops-platform` manifests that consume Kernel images
- `integration-mindburn-platform` release-candidate evidence
- SDK registries and GitHub/GHCR/Artifact Hub surfaces enumerated by
  `check_version_drift.py`
- Linear project “HELM Kernel v0.8.0 release train” and its issues

**Out of scope**:

- Claiming customer production, connector certification, or paid HELM GA from
  a Kernel artifact release alone.
- Force-merging failed permits, bypassing rulesets, or self-approving authority.
- Mass-deleting branches/worktrees before their unique commits and dirty files
  are classified.
- Committing the two user-owned tar archives.
- Adding unrelated features after the release candidate freezes.

## Git workflow

- Each implementation plan lands through its own fresh worktree/PR.
- Create the release-prep branch from fresh `origin/main` only after all feature
  and estate-resolution PRs are merged or explicitly closed as superseded.
- Suggested release branch: `release/v0.8.0`; release prep should be a narrow
  version/changelog/evidence PR, not a feature dump.
- Tag only the exact merged main commit whose deterministic gates and permit
  were evaluated.

## Steps

### Step 1: Build a live disposition ledger for every PR, branch, and worktree

Generate a machine-readable ledger from current Git/GitHub state. For every
open PR capture number, exact head SHA, branch, title, draft/review/check/permit
state, merge base, commits unique to head, overlapping PRs, and owner. For every
remote/local branch capture reachability from main and associated PR. For every
worktree capture path, branch/detached SHA, dirty/untracked files, locks, and
associated PR.

Classify each item exactly once:

- **merge**: valuable, current, non-duplicative, and capable of passing gates;
- **rework**: valuable but stale/conflicting/failing;
- **supersede**: behavior already present or included in Plans 001–004/another PR;
- **close-without-merge**: obsolete/unsafe/no longer desired, with rationale;
- **preserve pending authority**: cannot act until named owner/gate responds.

Do not clean anything in this step. Publish the ledger as a release evidence
artifact or Linear document that can be reviewed without exposing secrets.

**Verify**: counts from ledger equal live `gh pr list`, `for-each-ref`, and
`git worktree list`; every PR/branch/worktree has one disposition and no
unclassified unique commit or dirty file remains.

### Step 2: Resolve all open work into main or an explicit closed disposition

Work in dependency/risk order, not PR number order. For each merge candidate:
refresh from main, resolve conflicts in a fresh worktree, run focused and
required gates, push, then re-query exact-head checks/reviews/permit immediately
before merge. A push invalidates prior exact-head evidence.

CLI-specific handling:

- merge or faithfully incorporate PR #684 before changing verdict presentation;
- repair PR #679's failed permit, preserve its fail-closed refresh/transition
  model, then integrate its explicit watch TUI with Plan 002's terminal
  contract; its current plain view, unused width, and single-key approve/deny
  transitions must gain accessible layout, full decision context, and explicit
  confirmation; do not make it the global CLI shell;
- port only still-needed setup lifecycle behavior/tests from PR #562 into Plan
  003, then close #562 as superseded with commit links;
- fix or supersede #715 only after its kernel/contract failures are explained.

Apply the ledger discipline to all remaining PRs, including drafts and
Dependabot. The end condition is `gh pr list --state open` returning an empty
array, with each closed-unmerged PR carrying a truthful rationale and successor
link where applicable.

**Verify**: `gh pr list --state open --limit 250 --json number --jq length` →
`0`; `git log origin/main` contains every merge disposition; closed items are
traceable in the ledger.

### Step 3: Freeze and update the v0.8.0 release contract

Replace the stale v0.7.3 train with a v0.7.5 → v0.8.0 delta based on merged
source truth. Define release blockers:

- Plans 001–004 acceptance criteria;
- all security/authority PR dispositions;
- exact command/help and setup journey gates;
- signed artifacts and cross-platform binaries;
- docs/Artifact Hub propagation checks;
- authorized staging/production/rollback evidence;
- zero-open-PR and final-estate cleanup gates.

Run `make prepare-version VERSION=0.8.0` and review every changed version
surface. Generate/update the exact v0.8.0 OpenVEX, changelog, compatibility,
migration/deprecation notes, and release asset contract. Explain the `helm`
alias deprecation and canonical `helm-ai-kernel` command; do not silently drop
the alias if supported installs still rely on it.

**Verify**: `make version-drift && git diff --check` → exit 0; a literal search
finds no active release-train heading claiming v0.7.3 is the baseline and no
blocking v0.8.0 surface remains at 0.7.5.

### Step 4: Qualify the exact release candidate before tagging

From a clean release-candidate worktree at the exact proposed SHA run:

- `make quality-merge`
- `make quality-release`
- `make release-readiness`
- `make release-assets`
- Plan 001 destructive/help matrix
- Plan 003 Claude/Codex setup matrix
- Plan 004 CLI docs and completion matrix
- cross-platform artifact execution smoke, not compile alone
- reproducibility, checksum, SBOM, VEX, provenance, and cosign verification
- performance/size comparison with the audit baseline

Install the staged binaries into isolated macOS/Linux/Windows environments and
run `--version`, root/help/no-color, setup preview, doctor, first proof,
receipt verify, and destructive negative tests. Verify the release binary,
not a local dev build.

Attach exact logs/digests to the release candidate EvidencePack/permit input.
Run the distinct-provider permit and exact-head approval interlock. Do not tag
while any required result is skipped, stale, neutral, or failing.

**Verify**: all required checks are success for the exact SHA; permit receipt
binds that SHA and artifact digest; staged assets satisfy the declared contract.

### Step 5: Merge release prep, tag v0.8.0, and monitor every publisher

Merge only through normal policy after exact-head gates. Confirm main contains
the candidate unchanged, create/push signed/authorized tag `v0.8.0`, and monitor
the full tag workflow through its terminal jobs. Record the tag SHA, workflow
run ID, artifact checksums, attestations, cosign bundles, image/chart digests,
and publisher runs.

Do not stop when the GitHub Release appears. v0.7.5's release object existed
while the workflow was red. All post-release version-drift checks must pass in
the same release train, including Artifact Hub and rendered docs.

**Verify**: `gh run view <v0.8.0-run-id>` reports success for the complete
workflow; `gh release view v0.8.0` has every required asset and non-empty notes;
tag SHA equals the authorized main SHA.

### Step 6: Prove every public distribution surface

Run published drift until propagation is complete, fixing source-owned defects
rather than waiving them. Verify at minimum:

- GitHub release assets, checksums, provenance, SBOM, VEX, and cosign bundles;
- GHCR main/slim images by digest and OCI Helm chart 0.8.0;
- Artifact Hub shows chart 0.8.0/appVersion v0.8.0;
- Homebrew formula installs the canonical binary with a narrow direct command
  (`brew install mindburn-labs/tap/helm-ai-kernel`), without requiring a
  blanket tap trust step;
- npm, PyPI, crates.io, Maven Central, Go proxy/pkg.go.dev version parity;
- canonical docs render v0.8.0 install/setup/SDK examples;
- clean-machine CLI setup and proof succeeds from the published artifact.

If propagation is asynchronous, monitor; do not mark complete while red.

**Verify**: `make version-drift-published` → exit 0, and retained clean-machine
acceptance logs identify the published checksums/digests used.

### Step 7: Deploy through source-owned GitOps and prove runtime/rollback

Resolve the current topology and production source truth. Where an authorized
runtime consumes Kernel, update the owning GitOps manifest to the v0.8.0 image
digest through its own PR/review/permit/owner-approval path. Reconcile staging,
run smoke, retain receipt/EvidencePack refs, then promote to production only
with the required authority. Run live health, DENY/ESCALATE/ALLOW, receipt
verification, and setup/client integration probes appropriate to that slice.

Rehearse rollback to the prior known-good digest or produce current source-owned
rollback evidence. Re-promote v0.8.0 only after rollback proof passes.

If no Kernel runtime consumer exists, record that evidence and limit the claim
to public artifact deployment. Do not convert a package release into a hosted
production claim.

**Verify**: GitOps reports reconciled exact digest, runtime smoke/evidence is
source-owned and linked, and rollback evidence is accepted by the production
release authority.

### Step 8: Close release documentation and Linear truth

Update the Linear release project from the obsolete v0.7.3 baseline to the
actual v0.7.5 → v0.8.0 train. Close issues only with commit/PR/check/artifact/
deployment evidence appropriate to the issue. Publish a final status update
that separates merged, released, published, deployed, production-smoked, and
customer-accepted states.

Update active docs and release notes with canonical setup flow, terminal UX,
deprecations, migration, and verified install paths. Do not include internal
worktree/branch cleanup details in customer release notes.

**Verify**: no active Linear milestone/issue describes the baseline as v0.7.3;
all completed claims have direct evidence; docs truth and live rendering pass.

### Step 9: Remove proven-obsolete branches and worktrees safely

Only after release/deployment evidence is retained, regenerate the estate
ledger. For each non-main branch require one of:

- tip reachable from `origin/main`; or
- associated PR closed with its unique commits explicitly superseded/abandoned
  and recorded in the ledger.

For each worktree inspect `git status --porcelain=v1 --untracked-files=all` and
compare its HEAD/branch to the ledger. Preserve/copy user-owned dirty data only
with explicit operator direction; a dirty or unclassified worktree is a STOP,
not a `--force` invitation. Remove safe worktrees through `git worktree remove`,
then prune. Delete remote task branches with exact names and lease protection,
then local branches. Do not delete tags.

Preserve the two main-worktree tar archives unless the user separately directs
their disposition. End with the canonical repo on `main`, exact with
`origin/main`, and no other worktree/branch.

**Verify**:

- `git worktree list --porcelain | rg '^worktree ' | wc -l` → `1`
- `git for-each-ref --format='%(refname:short)' refs/heads` → `main`
- remote heads excluding symbolic HEAD → `origin/main` only
- `gh pr list --state open --json number --jq length` → `0`
- `git status --short --branch` → main aligned, only explicitly preserved
  user-owned untracked files if still present.

### Step 10: Issue the final release evidence statement

Produce one evidence-backed report containing:

- main and tag SHAs;
- merged/closed PR ledger and zero-open proof;
- CI, distinct-provider permit, and exact-head interlock receipts;
- artifact checksums, signatures/provenance, registry versions, and image/chart digests;
- docs, Homebrew, SDK, and clean-machine acceptance results;
- staging/production/rollback evidence or explicit no-runtime claim boundary;
- final branch/worktree counts;
- any customer/legal/broker acceptance explicitly outside Kernel release scope.

**Verify**: another operator can independently reproduce each claim from the
linked source-owned evidence; no claim relies on this plan or an RLM/audit note.

## Test plan

- All repository release gates plus Plans 001–004 acceptance suites.
- Published-binary journeys on Darwin arm64/amd64, Linux arm64/amd64, Windows amd64.
- Homebrew and direct-asset clean installs.
- Claude Code and Codex activation/trust-pending/receipt proof.
- JSON/plain/no-color/help/completion snapshots.
- Destructive negative paths and authorized fixture teardown.
- OCI image/chart startup, health, governance verdict, evidence, rollback.
- Post-release drift across every package/docs/chart surface.

## Done criteria

All must hold:

- [ ] Plans 001–004 are merged on main with required gates.
- [ ] All previously open PRs are merged or truthfully closed; open count is 0.
- [ ] v0.8.0 release prep is based on v0.7.5 and version drift is clean.
- [ ] Exact tag SHA has passing quality, permit, approval, and release workflows.
- [ ] Every declared artifact is signed/attested, public, and installable.
- [ ] Artifact Hub, docs, Homebrew, SDKs, GHCR, Go proxy, and GitHub agree on v0.8.0.
- [ ] Published CLI passes clean-machine setup and first-proof acceptance.
- [ ] Authorized GitOps deployment/runtime/rollback proof exists, or the
  artifact-only claim boundary is explicitly recorded.
- [ ] Linear and active docs reflect evidence-backed release truth.
- [ ] Only main remains locally/remotely and only the canonical worktree remains.
- [ ] User-owned untracked archives were not committed or deleted.
- [ ] Final evidence report is independently verifiable.
- [ ] `plans/README.md` status row is updated to DONE.

## STOP conditions

Stop and report if:

- any required review, ruleset, deterministic check, permit, approval interlock,
  owner approval, GitOps reconciliation, smoke, or rollback gate fails;
- a PR/branch/worktree contains unclassified unique or dirty user work;
- a push changes the candidate SHA after authority evidence was issued;
- a registry/docs surface cannot publish v0.8.0 or published drift remains red;
- deployment ownership or target is ambiguous in current source truth;
- cleanup would require broad force deletion or deleting a tag;
- completion would require claiming customer production/certification beyond
  the source-owned Kernel evidence.

## Maintenance notes

- Keep the estate ledger for future audits; delete branches/worktrees, not the
  disposition evidence.
- Make post-release drift a required terminal job so v0.7.5's partial-red state
  cannot be mistaken for success again.
- Release notes should celebrate the simpler CLI while security notes document
  destructive/help/preview hardening and compatibility aliases precisely.
