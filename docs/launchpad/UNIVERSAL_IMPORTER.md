---
title: Universal Launchpad Importer
last_reviewed: 2026-05-24
---

# Universal Launchpad Importer

Status: implemented as a safe, additive import and planning layer. The first
production slice inspects repositories, generates capability graphs,
LaunchRecipes, target plans, and untrusted AppSpec candidates. It does not run
unknown repository code or promote generated AppSpecs into the trusted registry.

## Product Contract

The importer turns a repository source into the existing Launchpad model:

```text
GitHub URL or local path
  -> SourceSnapshot
  -> CapabilityGraph
  -> LaunchRecipe
  -> Generated AppSpec candidate
  -> import preflight
  -> evidence-gated promotion
  -> normal Launchpad launch
```

Imported systems still use the same HELM objects as curated apps:
`AppSpec`, `LaunchPlan`, `LaunchRun`, receipts, EvidencePack refs, and teardown.
There are no framework-specific route trees or installer code paths.

## Detection Order

Detection is deterministic and ordered:

1. Framework-native contracts and adapter manifests.
2. Project manifests such as `package.json`, `pyproject.toml`, `Cargo.toml`,
   `go.mod`, Maven, and Gradle files.
3. Runtime manifests such as Dockerfile, Compose, Dev Container, Helm chart,
   and related deployment files.
4. Buildpack-style fallback when manifests exist but no runtime contract wins.
5. Generated wrapper only when confidence is low.
6. LLM reasoning may be used later for explanation and repair proposals, but
   not as the authoritative source of a launch recipe.

## Capability Graph

The graph records detected capabilities and risks:

- desktop UI
- API server
- worker
- agent framework
- MCP tools
- AG-UI stream
- sandbox needs
- persistence and ports
- required secrets and OAuth
- telemetry and test commands
- license and policy signals
- local, cloud, and hosted-sandbox target plans

Multi-module repositories are expected. A mixed desktop, service, and agent repo
is represented as one import with multiple modules and target plans.

## Adapter Manifests

Framework adapters live in `registry/launchpad/adapters/` and are validated by
`schemas/launchpad/framework_adapter.schema.json`.

Current adapters cover:

- LangGraph
- CrewAI
- OpenHands
- OpenAI Agents SDK
- Semantic Kernel
- Pydantic AI
- AutoGen
- generic Docker/Compose
- generic Tauri/Electron
- generic Node
- generic Python
- generic Rust

Explicit manifest evidence wins over generic runtime fallback. Generated
AppSpecs are always marked `oss_candidate`, `generated_untrusted`, and
`trusted=false`.

## API Surface

The Kernel exposes additive Launchpad import routes:

```text
POST /api/v1/launchpad/imports
GET  /api/v1/launchpad/imports
GET  /api/v1/launchpad/imports/{id}
POST /api/v1/launchpad/imports/{id}/preflight
POST /api/v1/launchpad/imports/{id}/promote
POST /api/v1/launchpad/imports/{id}/launch
POST /api/v1/launchpad/imports/{id}/teardown
```

`promote` and `launch` are intentionally evidence-gated. Until sandbox build,
SBOM, vulnerability scan, license review, smoke test, and teardown evidence are
available, generated imports remain blocked from LaunchKit execution.

## Current Boundary

Implemented now:

- GitHub REST metadata and bounded file inspection without full clone.
- Local-path imports for tests and self-hosted development.
- SourceSnapshot, CapabilityGraph, LaunchRecipe, TargetPlan, BuildStrategy,
  GeneratedAppSpecCandidate, ImportEvidenceLedger, and ImportPreflightResult.
- Console paste-box flow with Simple Mode and Developer Mode disclosure.
- Import records persisted under the Launchpad store.

Not implemented yet:

- Disposable sandbox build execution.
- Real SBOM and vulnerability scanner invocation.
- OCI image publication, Helm chart generation, GitOps commit generation, and
  OpenTofu module writing.
- Permission wallet spend/OAuth/host-permission grants.
- Trusted registry promotion.

Those features must be added behind evidence-producing backend routes, not UI
claims.
