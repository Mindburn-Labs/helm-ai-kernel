# Launchpad Execution Plan

## PR-1 Audit, Schemas, Architecture Docs

- [KEEP] Create Codex capability audit, repo audit, Spawn UX audit, orchestration plan, risk register, definition of done.
- [KEEP] Create `.codex/agents` task files.
- [KEEP] Add Launchpad app/substrate spec types, registry loader, validator, and matrix derivation.

## PR-2 Kernel CLI And Registry

- [KEEP] Implement `helm-ai-kernel launch matrix/apps/substrates/plan/status/logs/repair/delete`.
- [KEEP] Keep runtime side effects blocked until conformance.

## PR-3 Runtime And Installer

- [REBUILD] Implement local-container runtime and artifact-first installer.

## PR-4 App Specs And Policy Packs

- [REBUILD] Verify upstream licenses/releases for OpenClaw, Hermes, OpenCode, Kilo Code.
- [KEEP] Keep Codex, Claude Code, Cursor, and Junie as external/BYO adapters.

## PR-5 MCP, Receipts, EvidencePack

- [REBUILD] Wire MCP quarantine, approval receipts, launch receipts, teardown receipts, and EvidencePack export.

## PR-6 Cloud Stubs

- [REBUILD] Implement DigitalOcean/Hetzner dry-run and idempotency reconciliation.

## PR-7 Enterprise API

- [REBUILD] Add tenant Launchpad APIs, OpenAPI, route registry parity, and store.

## PR-8 Console UI

- [REBUILD] Build Launchpad Console flow over canonical APIs.

## PR-9 Conformance, Docs, Distribution

- [REBUILD] Add reference packs, security review, docs, and Homebrew naming plan.
