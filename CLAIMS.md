# HELM AI Kernel Claims

- Repo name: `helm-ai-kernel`
- Canonical role: Public HELM AI Kernel implementation: fail-closed execution kernel, CLI/API, SDK/contracts, receipts, replay/conformance surfaces, and local headless onboarding proof path.
- Public/private: Public OSS repo.
- HELM normative status: Canonical HELM AI Kernel under UCS v1.3.
- Current status: Active implementation with Go server, guardian evaluation, receipt storage/verification paths, API contracts, Dockerfile, Helm chart, tests, and docs.
- Implemented capabilities: Guardian decision evaluation, API/server wiring, receipt persistence and verification primitives, external host evidence ingestion/verification/correlation, deployment assets, conformance/test scaffolding, and Codex project-scoped setup/recovery with signed lifecycle evidence.
- Not implemented: No Console source code in this repo; no hosted Enterprise automation production claim; no named buyer production rollout claim; no L4 conformance claim; no eBPF, seccomp, TPM, hardware enclave, or packet-blocking enforcement claim unless a tested code path proves it.
- Public claims: HELM AI Kernel is the fail-closed execution firewall for AI agents; dangerous actions that reach a configured boundary must be denied or escalated before dispatch; receipts can be verified and tampering must fail; HELM can consume and correlate external host/network evidence without claiming host-level enforcement.
- Native-client boundary: Codex project setup stores an isolated project binding, recovery journal, and generated artifacts beneath a shared local authority. A matching config and Kernel-only synthetic denial are local setup evidence, not proof that a live Codex client loaded or obeyed the configuration. Claude Code setup resolves a direct CLI, requests MCP registration through that CLI, and writes selected hook configuration; it is not equivalent to the Codex project lifecycle or MCP-config readback.
- Claim evidence: `core/cmd/helm-ai-kernel`, `core/pkg/guardian`, `core/pkg/receipt`, `core/pkg/evidence/externalhost`, `core/pkg/correlation/hostaction`, `core/pkg/verifier/externalreceipt`, `api/openapi`, `Dockerfile`, `charts/helm-ai-kernel`, `README.md`.
- Tests that prove each claim: `go test ./...`, API contract checks, demo receipt smoke tests after API routes are enabled.
- Docs that mention each claim: `README.md`, `docs/`, `examples/`, deployment/runbook docs.
- Conformance boundary: Public CLI proof supports `L1` and `L2` level shortcuts. `L3` is source/test conformance coverage until a public CLI/API proof path is wired and tested. Higher levels are not public claims in this repo.
- Stale claims removed: Any unsupported hosted Enterprise automation, entitlement-enforcement, or production-conformance claim must remain absent until smoke-tested.
- Remaining gaps: Keep release/version claims tied to published GitHub release assets and docs gates.
- Verification commands: `make test` if available, `go test ./...`, API contract checks, Docker/Helm chart smoke commands from runbooks.
- Last audited date: 2026-07-14.
- Owner: Mindburn Labs.
