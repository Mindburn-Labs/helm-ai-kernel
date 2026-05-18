# Final Implementation Report

Status: expanded fail-closed Launchpad slice with additional mission-gate hardening. Not production ready and not 100% complete against the full mission because no OpenClaw or Hermes HELM-built signed OCI artifact has been recorded, `OPENROUTER_API_KEY` is not present in this environment for live OpenRouter e2e, and no app has full local-container e2e, teardown, receipt, and offline EvidencePack conformance.

## What Was Implemented

- [KEEP] Codex capability audit, repository audit, Spawn UX reference, orchestration plan, execution plan, risk register, definition of done, conformance docs, and security review docs.
- [KEEP] Kernel Launchpad CLI for `matrix`, `apps`, `substrates`, `plan`, guarded headless launch, `status`, `logs`, `repair`, and `delete --cascade`.
- [KEEP] Kernel Launchpad registry, schema validation, policy-pack parsing, stable matrix derivation, deterministic plan hashing, action IR, CPI adapter output, fixed verdict enum, fixed state enum, strict `oss_supported` promotion evidence, and `sha256:<64 lowercase hex>` supply-chain digest enforcement.
- [KEEP] Launchpad artifact CI workflow for pinned OpenClaw/Hermes refs: GHCR OCI image build, GitHub OIDC keyless cosign signing, cosign verification, syft SBOM generation, grype scan, and machine-readable artifact manifest publication.
- [KEEP] `helm-ai-kernel launch promote` tool and promotion package. Promotion remains blocked unless immutable image digest, cosign signature, syft SBOM, grype/trivy scan, provenance, live e2e, EvidencePack, and teardown refs are all present.
- [KEEP] Session executor/state machine with PEP/CPI-style fail-closed verdict handling and terminal invariants: no side-effect state without `ALLOW`, no `RUNNING` without launch, healthcheck, sandbox refs, and a runtime handle, and no `DELETED` without teardown receipt.
- [KEEP] Executor healthcheck runner path now blocks `RUNNING` unless a command healthcheck succeeds; failed healthchecks transition to `REPAIR_REQUIRED` and emit failure evidence instead of synthetic success.
- [KEEP] Artifact installer guardrails: digest-required install validation, immutable layout helpers, host `curl | bash` rejection, live-worktree mutation rejection, and install receipt data.
- [KEEP] Local-container runtime preflight and wrapper: deny-by-default filesystem/network posture, scoped workspace mount model, privilege-escalation guards, recursive launch guard, secret env projection, secret redaction, OpenRouter-only egress validation, and launch-scoped egress proxy receipt requirement.
- [KEEP] DigitalOcean and Hetzner dry-run/stub provisioners with canonical resource plans, idempotency keys, ambiguous outcome reconciliation, secret redaction, stale status pruning, and teardown receipts.
- [KEEP] Launchpad MCP governance package with launch-scoped authorization, unknown server/tool quarantine, schema pin enforcement, schema drift deny, side-effect approval receipt requirement, revoke enforcement, and fail-closed unavailable-registry behavior.
- [KEEP] Receipt writers and deterministic, verifier-compatible EvidencePack directory plus tar archive generation.
- [KEEP] Non-empty reference packs for OpenClaw, Hermes, and Codex local-container classifications. They verify offline but prove fail-closed classification, not successful app execution.
- [KEEP] Offline verifier now checks `00_INDEX.json` entry hashes against actual bundle bytes; Launchpad reference packs were updated from placeholder hashes to real SHA-256 values.
- [KEEP] Live conformance harness gate for CI manifest plus `OPENROUTER_API_KEY`; it refuses raw internet egress by requiring `HELM_LAUNCHPAD_EGRESS_PROXY_URL` and `HELM_LAUNCHPAD_EGRESS_PROXY_RECEIPT_REF`.
- [KEEP] OpenClaw and Hermes specs now encode the chosen HELM-built signed OCI direction, current upstream release tags, and OpenRouter egress allowlist while staying `oss_candidate`.
- [KEEP] OSS Launchpad API routes and OSS Console Launchpad feature backed by canonical runtime/session state.
- [KEEP] Enterprise Launchpad API, route registry, OpenAPI schemas, DB-backed LaunchRun store with in-memory fallback, GeneratedSpec/ActionProposal bridge, receipt/evidence refs, CompanyArtifactGraph refs, and teardown closure evidence.
- [KEEP] Enterprise Console Launchpad feature with workspace-scoped APIs, durable LaunchRun list/get rehydration, and enterprise-only evidence/approval refs.
- [KEEP] Enterprise recursive build race fixes for `ui-core-compat` and package asset copy so full `make build` and `make quality-pr` pass.
- [KEEP] Docs truth and public docs manifest coverage for Launchpad surfaces.
- [KEEP] Homebrew naming/package conflict plan without publishing a release claim.

## Exact Files Changed

Kernel OSS Launchpad:

- `apps/console/src/App.tsx`
- `apps/console/src/styles.css`
- `apps/console/src/features/launchpad/**`
- `core/cmd/helm-ai-kernel/launch_cmd.go`
- `core/cmd/helm-ai-kernel/launch_cmd_test.go`
- `.github/workflows/launchpad-artifacts.yml`
- `core/pkg/api/launchpad_handler.go`
- `core/pkg/api/launchpad_handler_test.go`
- `core/pkg/api/server.go`
- `core/pkg/launchpad/**`
- `docs/LAUNCHPAD.md`
- `docs/documentation-coverage.csv`
- `docs/launchpad/**`
- `docs/public-docs.manifest.json`
- `docs/source-inventory.manifest.json`
- `go.work`
- `policies/launchpad/**`
- `reference_packs/launchpad/**`
- `registry/launchpad/**`
- `schemas/launchpad/**`
- `tests/launchpad/**`

Enterprise Launchpad:

- `api/openapi/helm.openapi.yaml`
- `apps/console/src/features/launchpad/**`
- `apps/console/src/operator/components.tsx`
- `apps/console/src/operator/layout.tsx`
- `apps/console/src/operator/model.ts`
- `apps/console/src/operator/styles.css`
- `apps/console/src/router/routes.tsx`
- `apps/console/src/types/domain.ts`
- `apps/controlplane/internal/console/facade.go`
- `apps/controlplane/internal/console/launchpad_evidence.go`
- `apps/controlplane/internal/console/launchpad_routes.go`
- `apps/controlplane/internal/console/launchpad_routes_test.go`
- `apps/controlplane/internal/console/launchpad_service.go`
- `apps/controlplane/internal/console/launchpad_store.go`
- `apps/controlplane/internal/console/route_registry.go`
- `apps/controlplane/migrations/006_launchpad_runs.up.sql`
- `apps/controlplane/migrations/006_launchpad_runs.down.sql`
- `apps/controlplane/migrations/launchpad_runs_test.go`
- `docs/private/launchpad-commercial.md`
- `docs/public/launchpad.md`
- `docs/public/ownership.json`
- `e2e/tests/helpers/console.ts`
- `e2e/tests/launchpad.spec.ts`
- `packages/ui-core-compat/scripts/build-kernel-core.mjs`
- `packages/ui-core-compat/scripts/copy-assets.mjs`
- `packages/ui-core-compat/src/compat.tsx`
- `packages/ui-core-compat/src/index.ts`
- `scripts/copy-package-assets.ts`

Monorepo orchestration:

- `.codex/agents/00_director.md` through `.codex/agents/14_security_red_team.md`

## What Was Not Implemented

- [REBUILD] Successful live OpenClaw local-container e2e that reaches `RUNNING`.
- [REBUILD] Successful live Hermes local-container e2e that reaches `RUNNING`.
- [REBUILD] Successful OpenCode and Kilo Code local-container e2e.
- [REBUILD] Promotion of any app to `oss_supported`.
- [REBUILD] Executed CI output proving `cosign`, `syft`, and `grype`/`trivy` on real HELM-built OCI artifacts. The workflow and promotion gate exist, but no generated manifest has been recorded in this local repo.
- [REBUILD] Launch-scoped egress proxy sidecar implementation that a real Docker app container can use for OpenRouter traffic. The current runtime rejects raw egress and requires a proxy receipt; the actual proxy service/sidecar image is not implemented in this local slice.
- [REBUILD] Live MCP dispatch interception inside a running third-party app process.
- [DEFER] Live DigitalOcean/Hetzner provisioning. Dry-run/stub and live-mode guard logic exists; external writes were not run.
- [DEFER] Homebrew formula update and public website claim updates. Release claims remain blocked until successful app conformance.

## Blocked App/Substrate Matrix Cells

- `openclaw x local-container`: `oss_candidate`; current upstream release `v2026.5.12`; HELM OCI target planned; blocked on `OPENROUTER_API_KEY`, immutable image digest, cosign signature, syft SBOM, grype/trivy scan, real healthcheck, local-container e2e, teardown, receipt, and offline EvidencePack proof.
- `hermes x local-container`: `oss_candidate`; current upstream release `v2026.5.16`; HELM OCI target planned; blocked on `OPENROUTER_API_KEY`, immutable image digest, cosign signature, syft SBOM, grype/trivy scan, real healthcheck, local-container e2e, teardown, receipt, and offline EvidencePack proof.
- `opencode x local-container`: `oss_candidate`; blocked on full upstream artifact/e2e/healthcheck/teardown evidence.
- `kilocode x local-container`: `oss_candidate`; blocked on full upstream artifact/e2e/healthcheck/teardown evidence.
- `codex x local-container`: `external_proprietary_adapter`; BYO account/tool only, no redistribution or supported availability claim.
- `claude-code.external`, `cursor.external`, `junie.external`: `external_proprietary_adapter`; not redistributed by HELM.
- `digitalocean` and `hetzner`: dry-run/stub by default; live writes require `--dry-run=false`, provider token, approval receipt, and reconcile-before-retry.

## App Availability Classification

- `openclaw`: `oss_candidate`
- `hermes`: `oss_candidate`
- `opencode`: `oss_candidate`
- `kilocode`: `oss_candidate`
- `codex`: `external_proprietary_adapter`
- `claude-code.external`: `external_proprietary_adapter`
- `cursor.external`: `external_proprietary_adapter`
- `junie.external`: `external_proprietary_adapter`

No app is marked Available or `oss_supported`.

## Policy Packs Added

- App safe packs: OpenClaw, Hermes, OpenCode, Kilo Code.
- External adapter packs: Codex, Claude Code, Cursor, Junie.
- Substrate packs: local-container, DigitalOcean, Hetzner.

## Tests Added

- Kernel registry/session/install/runtime/MCP/provision tests.
- Kernel conformance readiness tests for missing `OPENROUTER_API_KEY`, signed OCI evidence requirements, and fully verified readiness.
- Kernel promotion tests and CLI dry-run promotion test for complete signed artifact manifests and mandatory evidence refs.
- Kernel local-container egress tests for OpenRouter-only allowlists and required egress proxy receipts.
- Kernel live conformance harness test gated by `HELM_LAUNCHPAD_LIVE_E2E`, CI artifact manifest, `OPENROUTER_API_KEY`, and egress proxy refs.
- Kernel verifier tamper test for `00_INDEX.json` hash mismatch.
- Kernel Launchpad API test for plan/launch/delete/evidence verification.
- Kernel `tests/launchpad` conformance tests for offline reference pack verification, missing model secret escalation, and unknown MCP quarantine.
- Enterprise Launchpad route/service tests for route registry, DB-backed reload, GeneratedSpec, ActionProposal, CompanyArtifactGraph, launch escalation, delete refs, and teardown closure evidence.
- Enterprise Launchpad Playwright spec across the configured browser matrix.

## Tests Passing

Kernel:

- `make build`
- `make test`
- `make test-console`
- `make test-platform`
- `make launch-ready`
- `make launch-security`
- `go test ./core/pkg/launchpad/... ./core/pkg/api -count=1`
- `go test ./core/pkg/verifier ./core/pkg/launchpad/...`
- `go test ./core/pkg/launchpad/...`
- `go test ./core/pkg/verifier`
- `go test ./core/pkg/mcp/...`
- `go test ./core/pkg/evidencepack/...`
- `go test ./core/cmd/helm-ai-kernel/...`
- `go test ./tests/launchpad/...`
- `actionlint .github/workflows/launchpad-artifacts.yml`
- `helm-ai-kernel launch matrix --json`
- `helm-ai-kernel launch plan openclaw local-container --json`
- `helm-ai-kernel launch openclaw local-container --headless --output json` returns `ESCALATED` for missing `OPENROUTER_API_KEY`, not a crash.
- `helm-ai-kernel launch status <launch_id> --json`
- `helm-ai-kernel launch logs <launch_id>`
- `helm-ai-kernel launch repair <launch_id>`
- `helm-ai-kernel launch delete <launch_id> --cascade`
- `helm-ai-kernel verify --bundle <generated EvidencePack directory>`
- `helm-ai-kernel verify --bundle <generated EvidencePack tar>`
- `go run ./core/cmd/helm-ai-kernel verify --bundle reference_packs/launchpad/openclaw-local-container`
- `go run ./core/cmd/helm-ai-kernel verify --bundle reference_packs/launchpad/hermes-local-container`
- `go run ./core/cmd/helm-ai-kernel verify --bundle reference_packs/launchpad/codex-local-container`

Enterprise:

- `corepack enable`
- `pnpm install`
- `make build`
- `make test`
- `make lint`
- `make verify-boundary`
- `make quality-pr`
- `make openapi-route-parity`
- `go test ./apps/controlplane/internal/console/... -count=1`
- `pnpm --dir apps/console test -- --run`
- `pnpm --dir apps/console build`
- `pnpm --dir e2e exec playwright test tests/launchpad.spec.ts --project=chromium`
- Full Enterprise `make test` and `make quality-pr` ran the configured Playwright matrix, including Launchpad in Chromium, Firefox, WebKit, and Mobile Chrome.

## Tests Failing Or Not Run

- [DEFER] `launchpad-artifacts` GitHub Actions workflow was not executed locally. It requires GHCR package write and GitHub OIDC.
- [DEFER] Live Docker app e2e for OpenClaw/Hermes/OpenCode/Kilo Code was not run to `RUNNING` because `OPENROUTER_API_KEY` is missing locally, no CI artifact manifest exists locally, and the real egress proxy sidecar is still a required external gate.
- [DEFER] Live cloud tests were not run; external writes require explicit operator approval and provider credentials.
- [DEFER] Live third-party app MCP dispatch was not run; MCP governance is tested at the Launchpad decision layer.
- [REBUILD] Current-turn Enterprise Playwright rerun failed before Launchpad assertions because the local dev server could not resolve `react`, `react-dom`, and `lucide-react` under `apps/console/node_modules`. I did not run package-manager repair in the current worktree.

## Risks Remaining

- [REBUILD] The mission end-state still requires real upstream artifact verification and successful app e2e before one-command launch can be advertised as available.
- [REBUILD] Artifact signature/SBOM/vulnerability evidence must be obtained for actual upstream artifacts before promotion.
- [REBUILD] Egress proxy sidecar must be implemented and exercised with real app containers before OpenRouter e2e can count as full runtime conformance.
- [REBUILD] Runtime Docker/network controls need a verified app happy path plus runtime-level negative tests against real containers.
- [REBUILD] Live MCP interception must be connected to running app tool dispatch, not only the governance decision package.
- [DEFER] Cloud live-mode behavior needs provider-backed opt-in validation outside normal CI.

## Security Review Result

- [KEEP] Fail-closed registry validation prevents unverified `oss_supported`.
- [KEEP] Missing model secret returns `ESCALATE`, not a crash.
- [KEEP] Missing OpenRouter e2e secret is now reported as `OPENROUTER_API_KEY`, not the logical `model_gateway` alias.
- [KEEP] `RUNNING` now requires a runtime start result with container and sandbox refs; synthetic allowed plans move to `REPAIR_REQUIRED` if runtime start fails.
- [KEEP] `00_INDEX.json` hash mismatch now fails offline verification.
- [KEEP] Promotion tool rejects incomplete signed artifact manifests and missing live e2e/EvidencePack/teardown refs.
- [KEEP] Local-container runtime rejects non-OpenRouter egress allowlists and requires an egress proxy receipt for OpenRouter allowlists.
- [KEEP] Unknown MCP server/tool quarantines or escalates.
- [KEEP] MCP schema drift denies, side-effect calls require approval receipts, and revoked tools are blocked.
- [KEEP] Host filesystem escape, non-deny network default, privileged container, privilege escalation flag, recursive launch, and secret projection leakage are covered by runtime preflight tests.
- [KEEP] Dirty package-manager/live worktree mutation and host `curl | bash` are covered by installer tests.
- [KEEP] Delete emits teardown receipt and updates EvidencePack material.
- [KEEP] OSS and Enterprise destructive teardown UI requires confirmation.
- [REBUILD] Live app/container red-team remains blocked until app e2e reaches a real container.

## Docs Updated

- Kernel Launchpad docs and schemas were added under `docs/LAUNCHPAD.md` and `docs/launchpad/`.
- Enterprise Launchpad public/private docs and ownership manifest were added.
- Docs intentionally avoid public availability or production-readiness claims.

## Release Steps

1. Complete upstream verification for OpenClaw and Hermes.
2. Obtain signed artifacts or signed source artifacts, sha256 digests, SBOMs, vulnerability scans, and license evidence.
3. Run `.github/workflows/launchpad-artifacts.yml` with GHCR package write and GitHub OIDC permissions.
4. Implement/provide the launch-scoped OpenRouter egress proxy sidecar and receipt source.
5. Run OpenClaw local-container e2e to `RUNNING`, then teardown, then offline EvidencePack verification.
6. Repeat for Hermes.
7. Keep OpenCode/Kilo Code as candidates until their evidence reaches the same bar.
8. Keep Codex and proprietary tools external/BYO unless redistribution and runtime e2e are proven.
9. Update Homebrew and public website claims only after conformance passes.

## Follow-Up PRs

- PR-3: Run Launchpad artifact workflow, record OpenClaw/Hermes signed OCI manifests, and verify cosign/syft/grype outputs.
- PR-4: Implement the real OpenRouter egress proxy sidecar and egress receipts for Docker local-container.
- PR-5: OpenClaw verified local-container e2e and runtime negative tests against a real container.
- PR-6: Hermes verified local-container e2e and promotion review.
- PR-7: OpenCode/Kilo Code upstream verification and blocker resolution.
- PR-8: live MCP interceptor binding and app-process dispatch receipts.
- PR-9: DigitalOcean/Hetzner opt-in live-mode validation with provider-backed reconciliation.
- PR-10: Homebrew and public claims after conformance evidence exists.
