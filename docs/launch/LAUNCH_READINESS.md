# HELM OSS Launch Readiness Checklist

This document tracks the final launch-readiness state of the `helm-oss` repository. It is updated mechanically by the `scripts/launch/launch-ready.sh` verification tool.

## Phase 0: Boundary Hardening
- [x] **PR Boundary**: No open PRs contain commercial infrastructure terminology.
- [x] **Config Boundary**: `wrangler.toml` does not enforce hosted domains.
- [ ] **Terminology Boundary**: `VERDICT_CANONICALIZATION.md` exists and resolves the ALLOW/DENY/ESCALATE vs. DEFER drift.
- [x] **Version**: `VERSION` is set to launch target `0.4.1`.
- [ ] **Homebrew**: README points to canonical `mindburnlabs/tap/helm`.

## Phase 1: Implementation & Proof
- [ ] **Build**: `make build` completes cleanly.
- [ ] **Test**: `make test` completes cleanly.
- [ ] **Demos**: `examples/launch` suite is present.
- [ ] **Console**: `apps/console` builds and runs locally without remote dependencies.
- [ ] **MCP**: MCP quarantine demo path is verified.
- [ ] **Proxy**: OpenAI base-url proxy demo path is verified.
- [ ] **Proof**: Evidence verification and tamper-failure paths are documented and verifiable.

## Phase 2: Community & Release
- [ ] **Issue Templates**: `bug_report`, `feature_request`, `docs_gap`, `integration_request`, `policy_example_request` are present.
- [ ] **Docs Sync**: `docs-coverage` and `docs-truth` checks pass.
- [ ] **Security**: `make launch-security` (vuln, secret, sbom) passes.
- [ ] **Release**: Dry-run release script confirms artifacts can be generated.

## Final Status
**CURRENT STATE: NOT READY**
