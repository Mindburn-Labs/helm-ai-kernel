# HELM AI Kernel Launch Readiness Checklist — 2026-05-19 snapshot

This is a frozen snapshot of one `scripts/launch/launch-ready.sh --write` run.
It is **not** a live status page and nothing keeps it current.

- Snapshot taken: 2026-05-19T17:15:07Z, against launch target `0.5.0`.
- `VERSION` is now `0.8.4`, and the tool derives its launch target from
  `cat VERSION`, so a fresh run would check a different target.
- The tool writes to `${HELM_LAUNCH_READY_REPORT}` and otherwise to
  `$LOG_DIR/launch-readiness.txt` in a `mktemp` directory. `make launch-ready`
  passes neither, so it never rewrites this file. This copy was produced by
  pointing `HELM_LAUNCH_READY_REPORT` here once and committing the result.
- The tool no longer emits the "Config Boundary: wrangler.toml…" row below;
  there is no `wrangler.toml` tracked in this repository.
- The "Homebrew" row below is a historical snapshot. Current active docs use
  the fully qualified formula `mindburn-labs/tap/helm-ai-kernel` so a second
  legacy tap cannot make an unqualified install ambiguous.

To get current state, run the tool rather than reading this file:

```bash
make launch-ready                                  # temp-file report, prints final status
HELM_LAUNCH_READY_REPORT=/tmp/launch-readiness.md \
  bash scripts/launch/launch-ready.sh --write      # same run, report at a path you choose
```

The tool exits non-zero unless every check passes, so its exit status — not a
committed checkbox — is the readiness signal.

## Snapshot contents (2026-05-19, launch target 0.5.0)

Last verification: 2026-05-19T17:15:07Z
Verification logs are emitted by the tool for each run and are intentionally
not committed to the repository.

### Phase 0: Boundary Hardening
- [x] **PR Boundary: No open PRs contain commercial infrastructure terminology.**
- [x] **Config Boundary: wrangler.toml does not enforce hosted domains.** (row no longer emitted)
- [x] **Terminology Boundary: VERDICT_CANONICALIZATION.md exists and resolves the ALLOW/DENY/ESCALATE vs. DEFER drift.**
- [x] **Version: VERSION is set to launch target 0.5.0.** (historical snapshot; current target is 0.8.4)
- [x] **Homebrew: README points to canonical mindburn-labs/tap/helm-ai-kernel.** (current active-doc command)

### Phase 1: Implementation & Proof
- [x] **Build: make build completes cleanly.**
- [x] **Test: make test completes cleanly.**
- [x] **Demos: examples/launch headless suite is present.**
- [x] **MCP: MCP quarantine demo path is verified.**
- [x] **Proxy: OpenAI base-url proxy demo path is verified.**
- [x] **Proof: Evidence verification and tamper-failure paths are documented and verifiable.**

### Phase 2: Community & Release
- [x] **Issue Templates: bug_report, feature_request, docs_gap, integration_request, policy_example_request are present.**
- [x] **Docs Sync: docs-coverage and docs-truth checks pass.**
- [x] **Release: Dry-run release script confirms artifacts can be generated.**

### Snapshot final status
**STATE AT 2026-05-19: READY** — for launch target 0.5.0 only.
