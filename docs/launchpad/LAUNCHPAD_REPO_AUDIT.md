# Launchpad Repo Audit

Date: 2026-05-17

## Scope

- [KEEP] Normative implementation scope is `helm-ai-kernel` and `helm-ai-enterprise`, per UCS v1.3.
- [REMOVE] Titan, Pilot, Mindburn website, docs-platform, and other sibling repos are not HELM conformance sources.
- [DEFER] Homebrew repos are distribution surfaces only.

## Existing Kernel Surfaces

- [KEEP] CLI dispatch is centralized in `core/cmd/helm-ai-kernel/main.go` and `core/cmd/helm-ai-kernel/registry.go`.
- [KEEP] Existing CLI commands include `mcp`, `sandbox`, `boundary`, `approvals`, `budget`, `evidence`, `verify`, `receipts`, `proxy`, `serve`, and conformance commands.
- [KEEP] MCP routes exist in `core/cmd/helm-ai-kernel/route_registry.go`: `/mcp`, `/mcp/v1/capabilities`, `/mcp/v1/execute`, MCP registry, scan, auth profiles, and authorize-call routes.
- [KEEP] Sandbox routes exist: `/api/v1/sandbox/profiles`, `/grants`, `/preflight`, and grant verification/inspection routes.
- [KEEP] Approval routes exist: `/api/v1/approvals`, WebAuthn challenge/assert, and transition routes.
- [KEEP] Budget routes exist: `/api/v1/budgets`, `/api/v1/budget/status`.
- [KEEP] Receipt and EvidencePack routes exist: `/api/v1/receipts`, `/api/v1/proofgraph/*`, `/api/v1/evidence/export`, `/api/v1/evidence/verify`, evidence envelopes, and replay verify.
- [KEEP] OSS Console exists in `apps/console` with kernel Console routes in `console_routes.go` and `console_agui_routes.go`.
- [REBUILD] No Launchpad-named registry, app/substrate specs, or CLI entrypoint existed before this work.

## Existing Enterprise Surfaces

- [KEEP] Enterprise route registry exists at `apps/controlplane/internal/console/route_registry.go`.
- [KEEP] GeneratedSpec paths exist in the route registry: `/generated-specs` and review/approve/execution-request/boundary-result/closure-evidence/close routes.
- [KEEP] CompanyArtifactGraph paths exist: `/company/artifacts`, `/company/graph`, `/company/edges`, `/company/conflicts`, `/company/drift`.
- [DEFER] Enterprise route registration is split across facade/server layers, increasing Launchpad route parity risk.
- [REBUILD] No enterprise Launchpad tenant API exists yet.

## Distribution And Docs

- [KEEP] Existing kernel launch-readiness docs and scripts are present under `docs/launch` and `scripts/launch`.
- [DEFER] Homebrew formula source exists in sibling tap repos, not as Launchpad runtime source.
- [REFACTOR] Existing docs use “launch” for release/demo readiness; Launchpad docs must avoid implying app-launch conformance until tests pass.

## Missing Launchpad Pieces

- [REBUILD] Full local-container runtime side effects.
- [REBUILD] Artifact-first installers with signed digest enforcement.
- [REBUILD] App upstream license/artifact/e2e verification for OpenClaw, Hermes, OpenCode, and Kilo Code.
- [REBUILD] Launch session store, receipts writer, EvidencePack generation, and offline verifier reference packs.
- [REBUILD] DigitalOcean/Hetzner provisioners beyond dry-run stubs.
- [REBUILD] Enterprise Launchpad APIs, OpenAPI parity, and Console UI.
- [REBUILD] Security red-team tests for malicious specs, MCP drift, filesystem escape, network egress bypass, and proprietary mislabeling.
