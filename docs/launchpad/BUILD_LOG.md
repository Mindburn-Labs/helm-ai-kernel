---
title: Launchpad Build Log
last_reviewed: 2026-05-24
---

# Launchpad Build Log

## 2026-05-24: Universal Importer Foundation

Scope:

- Added `core/pkg/launchpad/importer` as a safe repo-to-runtime planning layer
  around the existing Launchpad model.
- Added bounded GitHub REST inspection and local-path imports for tests and
  self-hosted development.
- Added SourceSnapshot, CapabilityGraph, LaunchRecipe, BuildStrategy,
  TargetPlan, GeneratedAppSpecCandidate, ImportPreflightResult, and
  ImportEvidenceLedger types.
- Added data-driven adapter manifests under `registry/launchpad/adapters/` for
  LangGraph, CrewAI, OpenHands, OpenAI Agents SDK, Semantic Kernel, Pydantic AI,
  AutoGen, generic Docker/Compose, generic Tauri/Electron, generic Node,
  generic Python, and generic Rust.
- Added `schemas/launchpad/framework_adapter.schema.json`.
- Added additive Launchpad import routes and route-registry/OpenAPI entries:
  `POST /imports`, `GET /imports`, `GET /imports/{id}`,
  `POST /imports/{id}/preflight`, `POST /imports/{id}/promote`,
  `POST /imports/{id}/launch`, and `POST /imports/{id}/teardown`.
- Added Console paste-box UI for imports. Simple Mode shows repo state,
  detected capabilities, target plans, and preflight. Developer Mode exposes
  the capability graph, LaunchRecipe, evidence ledger, and raw preflight data.

Repo-truth boundary:

- Generated imports are persisted and visible, but remain `generated_untrusted`.
- Import preflight records source, graph, license, quarantine, SBOM, scan, and
  smoke-test checks. Pending SBOM, scan, and smoke-test evidence keeps imports
  blocked from trusted promotion.
- `promote` returns evidence requirements and generated candidates only.
- `launch` is blocked until trusted registry promotion exists. No unknown repo
  code is executed in this pass.

Focused verification completed:

```bash
go test ./core/pkg/launchpad/importer ./core/cmd/helm-ai-kernel -run 'TestAnalyzerImport|TestBuildStrategy|TestPreflight|TestLaunchpadImportRoutes' -count=1
cd apps/console && npm run typecheck
cd apps/console && npm run test
cd apps/console && npm run build
cd apps/console && npm run smoke
cd apps/console && npm run smoke:browser
go test ./core/cmd/helm-ai-kernel ./core/pkg/api ./core/pkg/launchkit ./core/pkg/launchpad/... -count=1
make test-console
make docs-truth
make launch-api-truth
make release-readiness
```

## 2026-05-22: Unified Launchpad Repo-Truth Pass

Scope:

- Kept one Kernel Console Launchpad route and existing Launchpad API family.
- Refactored the Console surface into shared components for app cards, simple
  launch flow, run timeline, proof, developer disclosure, and entitlement gate
  rendering.
- Removed hardcoded Hermes-only Simple Mode claims and green-path copy.
- Removed raw secret input behavior from Simple Mode. Secret setup now binds
  environment variable names through the existing secret route contract.
- Removed the UI-only custom AppSpec launch card from the registry app grid.
- Added optional TypeScript fields for future backend entitlement decisions.
  Production code does not infer account tier.
- Documented Mindburn hosted account and entitlement integration as target
  architecture in `MINDBURN_ACCOUNT_ENTITLEMENTS_SPEC.md`.

Repo-truth boundary:

- Current Kernel implementation has Launchpad/LaunchKit, supported registry
  apps, proof refs, EvidencePack export, MCP, sandbox, secrets, and teardown.
- Current Kernel implementation does not have production Free / Individual /
  Enterprise hosted entitlement routes.
- Fixture-only entitlement states are allowed in tests and must remain labeled
  as fixtures.

Verification targets:

```bash
cd apps/console
npm run typecheck
npm run test
npm run build
npm run smoke
npm run smoke:browser
go test ./core/cmd/helm-ai-kernel ./core/pkg/api ./core/pkg/launchkit ./core/pkg/launchpad/... -count=1
make test-console
make docs-truth
make launch-api-truth
make release-readiness
```
