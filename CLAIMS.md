# HELM AI Kernel Claims

- Repo name: `helm-ai-kernel`
- Canonical role: Public HELM AI Kernel implementation: fail-closed execution kernel, CLI/API, SDK/contracts, receipts, replay/conformance surfaces, and headless API engine for external clients.
- Public/private: Public OSS repo.
- HELM normative status: Canonical HELM AI Kernel under UCS v1.3.
- Current status: Active implementation with Go server, guardian evaluation, receipt storage/verification paths, API contracts, Dockerfile, Helm chart, tests, and docs.
- Implemented capabilities: Guardian decision evaluation, API/server wiring, receipt persistence and verification primitives, external host evidence ingestion/verification/correlation, deployment assets, conformance/test scaffolding.
- Not implemented: No bundled browser console; no claim of full L2/L3 conformance; no production customer deployment claim; no eBPF, seccomp, TPM, TEE, or packet-blocking enforcement claim unless a tested code path proves it.
- Public claims: HELM AI Kernel is the fail-closed execution firewall for AI agents; dangerous actions must be denied or escalated before dispatch; receipts can be verified and tampering must fail; HELM can consume and correlate external host/network evidence without claiming host-level enforcement.
- Claim evidence: `core/cmd/helm-ai-kernel`, `core/pkg/guardian`, `core/pkg/receipt`, `core/pkg/evidence/externalhost`, `core/pkg/correlation/hostaction`, `core/pkg/verifier/externalreceipt`, `api/openapi`, `Dockerfile`, `charts/helm-ai-kernel`, `README.md`.
- Tests that prove each claim: `go test ./...`, API contract checks, demo receipt smoke tests after API routes are enabled.
- Docs that mention each claim: `README.md`, `docs/`, `examples/`, deployment/runbook docs.
- Stale claims removed: Any unsupported bundled-console or production-conformance claim must remain absent until smoke-tested.
- Remaining gaps: Publish release tag/version after final local gates pass.
- Verification commands: `make test` if available, `go test ./...`, API contract checks, Docker/Helm chart smoke commands from runbooks.
- Last audited date: 2026-05-06.
- Owner: Mindburn Labs.
