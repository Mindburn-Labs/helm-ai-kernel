# Final Implementation Report

Status: expanded fail-closed Skill Packs + Launchpad + Commercial governance slice. Not production ready and not 100% complete.

`mission_100_percent_complete` remains false. OpenClaw and Hermes have not been promoted by signed artifact and live local-container evidence, the GitHub artifact workflow has not produced release evidence in this workspace, Enterprise `make verify-boundary` still fails on mirrored kernel/protocol drift, and Commercial Launchpad remains a fail-closed tenant shell rather than a live OSS-runtime delegation path.

## What Was Implemented

- [KEEP] Kernel Launchpad remains fail-closed: candidate apps cannot become supported without license, artifact, policy, sandbox, healthcheck, e2e, teardown, receipts, and EvidencePack refs.
- [KEEP] HELM-owned OpenClaw and Hermes OCI build recipes were added under `tools/launchpad/artifacts/`, preserving upstream license notices and avoiding dependence on upstream Dockerfiles.
- [KEEP] `.github/workflows/launchpad-artifacts.yml` now has build/sign, live conformance, and merged promotion manifest phases. The manifest binds artifact refs, e2e refs, teardown refs, and EvidencePack refs to the current GitHub run.
- [KEEP] `launch promote` now accepts the merged promotion manifest and rejects missing refs, non-immutable images, mismatched digests, failed scans, missing cosign/SBOM/vuln/provenance refs, and refs not tied to the current workflow run.
- [KEEP] Launch-owned OpenRouter CONNECT proxy support exists for local-container egress. It only permits `api.openrouter.ai:443` and `openrouter.ai:443`, emits egress receipts, and redacts secret material.
- [KEEP] Session execution now refuses `RUNNING` for networked launches unless runtime returns an egress receipt in addition to container, sandbox, launch, healthcheck, and EvidencePack refs.
- [KEEP] The live conformance harness no longer uses synthetic container IDs. It drives Docker-backed runtime startup and app-specific `helm-launchpad-openrouter-check` healthchecks, so it will truthfully fail without real signed images and a fresh `OPENROUTER_API_KEY`.
- [KEEP] EvidencePack export copies all files referenced by `00_INDEX.json`, and conform verification accepts generated top-level signature/hash sidecars.
- [KEEP] OSS Skill Packs were added as a first-class package separate from Forge: search, inspect, verify, scan, install, export, list, disable, revoke, receipt, marketplace, and plugin commands.
- [KEEP] Skill Pack typed and schema-backed validation now checks manifest fields, status/scope/risk enums, content hash, publisher key refs, safe policy TOML keys, and the rule that skills do not grant tool authority.
- [KEEP] First-party Skill Packs use a trusted publisher keyring policy/ref check. This is not yet full public-key cryptographic signing.
- [KEEP] Remote GitHub Skill Pack fetch exists for refs of the form `github:owner/repo/path@ref#sha256:<digest>` and rejects mutable branch refs and digestless fetches.
- [KEEP] Repo-scoped Codex projection writes `.agents/skills/<publisher>/<skill>/SKILL.md` with install/projection/revoke receipts.
- [KEEP] Codex plugin export writes `.codex-plugin/plugin.json`, bundled skill files, pending/quarantined MCP metadata, and off-by-default hooks.
- [KEEP] First-party `helm/repo-auditor` and `helm/codex-multi-agent-director` Skill Packs were added.
- [KEEP] Skill Pack schemas, scanner negative-vector tests, projection coverage, plugin export coverage, and Skill/Launchpad flow catalogs were added without claiming production readiness.
- [KEEP] Enterprise Launchpad tenant APIs, route registry entries, OpenAPI schemas, migration, DB-backed/in-memory LaunchRun store, GeneratedSpec/CompanyArtifactGraph refs, and fail-closed plan/launch/repair/delete behavior were added.
- [KEEP] Enterprise Skills routes now cover candidate scan, install, rollout, receipts, usage, and drift in addition to the earlier list/candidate/promote/reject/revoke paths.
- [KEEP] Enterprise route registry and OpenAPI parity pass for the added Launchpad and Skills route inventory.
- [KEEP] Enterprise Console has a Launchpad feature route with app/substrate matrix, grant/policy/MCP/receipt panels, repair, and two-step teardown rendering canonical API/store state.
- [KEEP] Enterprise Launchpad Playwright coverage passes across the broad suite and the focused Chromium Launchpad spec.
- [KEEP] Kernel and Enterprise Console package resolution issues were repaired; direct Console build/test gates pass.

## Exact Files Changed

Kernel worktree:

- `.github/workflows/launchpad-artifacts.yml`
- `apps/console/vite.config.ts`
- `core/cmd/helm-ai-kernel/export_cmd.go`
- `core/cmd/helm-ai-kernel/launch_cmd.go`
- `core/cmd/helm-ai-kernel/launch_cmd_test.go`
- `core/cmd/helm-ai-kernel/skills_cmd.go`
- `core/cmd/helm-ai-kernel/skills_cmd_test.go`
- `core/pkg/conform/evidencepack.go`
- `core/pkg/launchpad/promotion/manifest.go`
- `core/pkg/launchpad/promotion/manifest_test.go`
- `core/pkg/launchpad/runtime/container_network.go`
- `core/pkg/launchpad/runtime/egress_proxy.go`
- `core/pkg/launchpad/runtime/local_container.go`
- `core/pkg/launchpad/runtime/local_container_test.go`
- `core/pkg/launchpad/session/executor.go`
- `core/pkg/launchpad/session/executor_test.go`
- `core/pkg/launchpad/session/runtime_starter.go`
- `core/pkg/skillpacks/files.go`
- `core/pkg/skillpacks/github.go`
- `core/pkg/skillpacks/hash.go`
- `core/pkg/skillpacks/loader.go`
- `core/pkg/skillpacks/plugin.go`
- `core/pkg/skillpacks/projection.go`
- `core/pkg/skillpacks/receipts.go`
- `core/pkg/skillpacks/scanner.go`
- `core/pkg/skillpacks/skillpacks_test.go`
- `core/pkg/skillpacks/types.go`
- `core/pkg/skillpacks/validation.go`
- `docs/documentation-coverage.csv`
- `docs/launch/LAUNCH_READINESS.md`
- `docs/launchpad/CONFORMANCE.md`
- `docs/launchpad/FINAL_IMPLEMENTATION_REPORT.md`
- `docs/launchpad/FLOW_CATALOG.md`
- `docs/launchpad/SECURITY_REVIEW.md`
- `docs/launchpad/final_report.json`
- `docs/public-docs.manifest.json`
- `docs/skills/CODEX_CAPABILITY_AUDIT.md`
- `docs/skills/FLOW_CATALOG.md`
- `docs/skills/SKILL_PACK_REPO_AUDIT.md`
- `policies/skills/first-party.safe.toml`
- `registry/skills/helm/codex-multi-agent-director/SKILL.md`
- `registry/skills/helm/codex-multi-agent-director/skillpack.json`
- `registry/skills/helm/repo-auditor/SKILL.md`
- `registry/skills/helm/repo-auditor/skillpack.json`
- `schemas/skills/skillpack.v1.schema.json`
- `schemas/skills/skillpolicy.v1.schema.json`
- `schemas/skills/skillreceipt.v1.schema.json`
- `schemas/skills/skillscan.v1.schema.json`
- `tests/launchpad/live_conformance_test.go`
- `tools/launchpad/artifacts/README.md`
- `tools/launchpad/artifacts/hermes.Dockerfile`
- `tools/launchpad/artifacts/openclaw.Dockerfile`

Enterprise worktree:

- `api/openapi/helm.openapi.yaml`
- `apps/controlplane/internal/console/facade.go`
- `apps/controlplane/internal/console/facade_test.go`
- `apps/controlplane/internal/console/launchpad_evidence.go`
- `apps/controlplane/internal/console/launchpad_routes.go`
- `apps/controlplane/internal/console/launchpad_routes_test.go`
- `apps/controlplane/internal/console/launchpad_service.go`
- `apps/controlplane/internal/console/launchpad_store.go`
- `apps/controlplane/internal/console/route_registry.go`
- `apps/controlplane/internal/console/skills_routes.go`
- `apps/controlplane/internal/console/skills_routes_test.go`
- `apps/controlplane/internal/store/postgres/store.go`
- `apps/controlplane/migrations/006_launchpad_runs.down.sql`
- `apps/controlplane/migrations/006_launchpad_runs.up.sql`
- `apps/console/src/features/launchpad/LaunchpadPage.tsx`
- `apps/console/src/features/launchpad/api.ts`
- `apps/console/src/features/launchpad/components/AppPicker.tsx`
- `apps/console/src/features/launchpad/components/GrantReviewPanel.tsx`
- `apps/console/src/features/launchpad/components/LaunchMatrix.tsx`
- `apps/console/src/features/launchpad/components/LaunchReceiptsPanel.tsx`
- `apps/console/src/features/launchpad/components/LaunchStatusPanel.tsx`
- `apps/console/src/features/launchpad/components/McpQuarantinePanel.tsx`
- `apps/console/src/features/launchpad/components/PolicyPackPanel.tsx`
- `apps/console/src/features/launchpad/components/RepairPanel.tsx`
- `apps/console/src/features/launchpad/components/SubstratePicker.tsx`
- `apps/console/src/features/launchpad/components/TeardownPanel.tsx`
- `apps/console/src/features/launchpad/hooks.ts`
- `apps/console/src/features/launchpad/store.ts`
- `apps/console/src/features/launchpad/types.ts`
- `apps/console/src/operator/components.tsx`
- `apps/console/src/operator/layout.tsx`
- `apps/console/src/operator/model.ts`
- `apps/console/src/router/lazyPages.tsx`
- `apps/console/src/router/routes.test.tsx`
- `apps/console/src/router/routes.tsx`
- `apps/console/src/types/domain.ts`
- `apps/console/vite.config.ts`
- `core/pkg/console/server_chat_context.go`
- `core/pkg/console/server_chat_evaluator.go`
- `docs/private/skills-launchpad-commercial-flow-catalog.md`
- `e2e/tests/helpers/console.ts`
- `e2e/tests/launchpad.spec.ts`
- `scripts/ci/23_console_migration_validation.sh`

## What Was Not Implemented

- [REBUILD] OpenClaw live local-container e2e to `RUNNING` with fresh CI `OPENROUTER_API_KEY`.
- [REBUILD] Hermes live local-container e2e to `RUNNING` with fresh CI `OPENROUTER_API_KEY`.
- [REBUILD] GitHub Actions artifact run producing recorded GHCR digests, keyless cosign verification output, syft SBOMs, grype/trivy reports, provenance, and merged promotion manifest.
- [REBUILD] Promotion of any app to `oss_supported`.
- [REBUILD] Full live Docker network proof that OpenClaw/Hermes app containers have no raw egress and reach OpenRouter only through the Launchpad proxy sidecar.
- [REBUILD] Live MCP dispatch interception inside a running app process.
- [REFACTOR] First-party Skill Pack signature checking is keyring/ref/content-hash based; public-key cryptographic signature verification remains incomplete.
- [REFACTOR] Enterprise Launchpad still needs live approved OSS runtime delegation, approval workflow integration, persistent retention policy behavior, fleet governance, and incident mode.
- [REBUILD] Enterprise mirrored kernel/protocol drift blocks `make verify-boundary`.
- [DEFER] Live DigitalOcean/Hetzner writes. Dry-run/stub remains the default.
- [DEFER] Homebrew formula update and public website claims.

## Blocked App/Substrate Matrix Cells

- `openclaw x local-container`: `oss_candidate`; blocked on signed OCI manifest, cosign/SBOM/vuln/provenance refs, fresh CI OpenRouter e2e, real container healthcheck, teardown receipt, and offline EvidencePack proof.
- `hermes x local-container`: `oss_candidate`; blocked on the same evidence gates as OpenClaw.
- `opencode x local-container`: `oss_candidate`; blocked on full artifact and runtime conformance.
- `kilocode x local-container`: `oss_candidate`; blocked on full artifact and runtime conformance.
- `codex x local-container`: `external_proprietary_adapter`; BYO only.
- `claude-code.external`, `cursor.external`, `junie.external`: `external_proprietary_adapter`; no redistribution.
- `digitalocean` and `hetzner`: dry-run/stub by default; live mode requires explicit approval receipt and reconciliation.

## App Availability Classification

- `openclaw`: `oss_candidate`
- `hermes`: `oss_candidate`
- `opencode`: `oss_candidate`
- `kilocode`: `oss_candidate`
- `codex`: `external_proprietary_adapter`
- `claude-code.external`: `external_proprietary_adapter`
- `cursor.external`: `external_proprietary_adapter`
- `junie.external`: `external_proprietary_adapter`

No app is Available or `oss_supported`.

## Policy Packs Added

- App safe packs: OpenClaw, Hermes, OpenCode, Kilo Code.
- External adapter packs: Codex, Claude Code, Cursor, Junie.
- Substrate packs: local-container, DigitalOcean, Hetzner.
- Skill packs: first-party safe policy for repo-scoped skills.

## Tests Added

- Kernel workflow-bound promotion manifest tests.
- Kernel runtime egress proxy tests.
- Kernel session invariant tests requiring egress receipts for networked `RUNNING` launches.
- Kernel live conformance harness tests that use Docker-backed runtime instead of synthetic container IDs.
- Kernel EvidencePack export/verify regression coverage through launch readiness gates.
- Kernel Skill Packs scanner, signature-ref validation, pinned GitHub ref parsing, projection, plugin export, marketplace, and CLI tests.
- Enterprise Skills route tests for scan, install, rollout, receipts, usage, and drift.
- Enterprise Launchpad route/store/service tests for matrix, plan evidence refs, launch escalation, teardown receipt invariants, and workspace scoping.
- Enterprise Console Launchpad unit and Playwright coverage.

## Tests Passing

Kernel:

- `make build`
- `make test`
- `make test-console`
- `make test-platform`
- `make launch-ready`
- `make launch-security`
- `go test ./core/pkg/skillpacks/...`
- `go test ./core/pkg/launchpad/...`
- `go test ./core/cmd/helm-ai-kernel/...`
- `go test ./tests/launchpad/...`
- `go test ./core/pkg/mcp/...`
- `go test ./core/pkg/evidencepack/...`

Enterprise:

- `make build`
- `make test`
- `make lint`
- `make openapi-route-parity`
- `go test ./apps/controlplane/internal/console/...`
- `go test ./apps/controlplane/internal/store/postgres`
- `pnpm --dir apps/console typecheck`
- `pnpm --dir apps/console test -- --run`
- `pnpm --dir apps/console build`
- `pnpm --dir e2e exec playwright test tests/launchpad.spec.ts --project=chromium`
- Broad `make test` Playwright suite: 89 tests passed.

## Tests Failing Or Not Run

- [REBUILD] `make verify-boundary` fails in Enterprise with 12 mirrored kernel/protocol files modified relative to `helm-ai-kernel.lock`.
- [REBUILD] `make quality-pr` remains blocked by the same boundary violation.
- [DEFER] GitHub `launchpad-artifacts` workflow was not executed locally because it requires GHCR write and GitHub OIDC.
- [DEFER] Live OpenClaw/Hermes Docker e2e was not run because no fresh signed CI artifact manifest and no fresh CI-scoped OpenRouter key evidence exist locally.
- [DEFER] Live cloud provider tests were not run.
- [DEFER] Live third-party app MCP dispatch was not run.
- [DEFER] Codex UI plugin install smoke and Claude Code/Cursor/OpenCode projection smokes were not run.

## Risks Remaining

- [REBUILD] No app has full conformance evidence.
- [REBUILD] The chat-pasted OpenRouter key is treated as compromised and is not valid release evidence.
- [REBUILD] Artifact workflow changes exist, but no recorded signed artifact manifest exists.
- [REBUILD] Real Docker app-container proxy attachment is not yet proven by CI.
- [REFACTOR] Skill Pack signature validation is not yet public-key cryptographic verification.
- [REFACTOR] Enterprise Launchpad surfaces exist but remain fail-closed tenant governance; they do not yet execute live OSS runtime delegation or complete commercial approval/retention workflows.
- [REBUILD] Enterprise boundary drift blocks `verify-boundary` and `quality-pr`.
- [DEFER] Live provider and live app MCP dispatch behavior remain unproven.

## Security Review Result

[KEEP] Current kernel paths fail closed for missing conformance, missing secrets, unsafe egress allowlists, unknown MCP tools, missing promotion evidence, bad EvidencePack hashes, host installer patterns, invalid terminal states, unsigned/missing Skill Pack metadata, mutable GitHub skill refs, and Enterprise launch/skill actions without approvals.

[REBUILD] Production security sign-off remains blocked until live app containers, real sidecar/proxy attachment, app-process MCP dispatch, signed artifacts, Enterprise live runtime delegation, Enterprise boundary sync, and full commercial approval/retention workflows are proven.

## Docs Updated

- Kernel Launchpad conformance, security, final report, readiness, docs coverage, and public docs manifest.
- Kernel Skill Pack audits and flow catalog.
- Kernel Launchpad flow catalog.
- Commercial private Skill/Launchpad flow catalog.

Docs continue to avoid public availability claims.

## Release Steps

1. Revoke the chat-pasted OpenRouter key and configure a fresh scoped `OPENROUTER_API_KEY` in CI.
2. Run the artifact workflow in GitHub with GHCR package write and OIDC signing.
3. Record signed OpenClaw/Hermes OCI digests, cosign signatures, SBOMs, vuln scans, provenance, e2e refs, teardown refs, and EvidencePack refs.
4. Prove Docker container attachment to the Launchpad egress proxy.
5. Run OpenClaw and Hermes to `RUNNING`, delete each launch, and verify EvidencePacks offline from directory and tar.
6. Wire Enterprise Launchpad to approved OSS runtime delegation and complete approval/evidence retention workflows.
7. Clear Enterprise mirrored kernel/protocol drift through the approved OSS sync path.
8. Complete Skill Pack public-key signature verification and broader projection smokes.
9. Promote apps only through `helm-ai-kernel launch promote` after all required refs exist.
10. Update Homebrew and public claims only after conformance passes.

## Follow-Up PRs

- PR-3: artifact workflow execution and signed manifest recording.
- PR-4: Docker sidecar/proxy network proof.
- PR-5: OpenClaw local-container e2e and promotion review.
- PR-6: Hermes local-container e2e and promotion review.
- PR-7: Enterprise Launchpad live runtime delegation, approval workflow, and evidence retention completion.
- PR-8: Enterprise OSS sync to clear boundary drift.
- PR-9: live MCP app-process dispatch receipts.
- PR-10: Skill Pack public-key cryptographic signatures and broader projection smoke coverage.
- PR-11: Homebrew and public claims after conformance.
