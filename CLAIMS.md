# HELM OSS Claims

- Repo name: `helm-oss`
- Canonical role: Public HELM OSS implementation: fail-closed execution kernel, CLI/API, SDK/contracts, receipts, replay/conformance surfaces, and self-hostable console.
- Public/private: Public OSS repo.
- HELM normative status: Canonical HELM OSS under UCS v1.3.
- Current status: Active implementation with Go server, guardian evaluation, receipt storage/verification paths, console app, Dockerfile, Helm chart, tests, and docs.
- Implemented capabilities: Guardian decision evaluation, API/server wiring, receipt persistence and verification primitives, console app, deployment assets, conformance/test scaffolding.
- Not implemented: No live public proof console until `oss.mindburn.org` DNS/deployment passes smoke; no claim of full L2/L3 conformance; no production customer deployment claim.
- Public claims: HELM OSS is the fail-closed execution firewall for AI agents; dangerous actions must be denied or escalated before dispatch; receipts can be verified and tampering must fail.
- Claim evidence: `core/cmd/helm`, `core/pkg/guardian`, `core/pkg/receipt`, `apps/console`, `Dockerfile`, `charts/helm-oss`, `README.md`.
- Tests that prove each claim: `go test ./...`, console tests where present, demo receipt smoke tests after API routes are enabled.
- Docs that mention each claim: `README.md`, `docs/`, `examples/`, deployment/runbook docs.
- Stale claims removed: Any unsupported live-console or production-conformance claim must remain absent until smoke-tested.
- Remaining gaps: Deploy and smoke-test public proof console; publish release tag/version after final local gates pass.
- Verification commands: `make test` if available, `go test ./...`, console test command from `apps/console`, Docker/Helm chart smoke commands from runbooks.
- Last audited date: 2026-05-06.
- Owner: Mindburn Labs.
