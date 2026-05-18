# Agent Orchestration Plan

## Handoffs

- [KEEP] 00 Director blocks claims until 01, 02, 03, and 14 are complete.
- [KEEP] 01 Repo Cartographer feeds 04, 10, 11, 12, and 13.
- [KEEP] 02 Codex Changelog Auditor feeds Codex app classification and policy pack constraints.
- [KEEP] 03 Spawn Reverse Engineer feeds CLI UX only.
- [KEEP] 04 Kernel Launch Architect owns the OSS CLI and registry base before runtime side effects.
- [KEEP] 05, 07, 08, and 09 depend on 04 schemas and plan contracts.
- [KEEP] 10 depends on 04 plan semantics and 01 enterprise route audit.
- [KEEP] 11 depends on 04 and 10 API contracts.
- [KEEP] 12 and 14 gate all Available classifications.
- [KEEP] 13 updates docs/distribution only after 12 and 14.

## Blocking Dependencies

- [REBUILD] No app can move to `oss_supported` before QA conformance and security review pass.
- [REBUILD] No cloud live provisioner can run before explicit human approval and idempotency reconciliation tests.
- [REBUILD] No enterprise route can merge without OpenAPI and route-registry parity.

## Final Merge Gates

- [KEEP] Codex audit, repo audit, Spawn audit, execution plan, risk register, definition of done, final report, and security review exist.
- [KEEP] CLI builds and matrix/plan commands work.
- [KEEP] OpenClaw/Hermes/Codex cells are either verified or explicitly blocked/classified.
- [KEEP] Unknown MCP tool quarantines.
- [KEEP] Teardown emits receipt and EvidencePack verifies offline before any app is Available.
