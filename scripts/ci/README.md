# Ci
<!-- docs-generated: surface-readme -->

## Purpose

Active tooling surface for the `helm-oss` project.

## Canonical Interface

- Source path: `scripts/ci`
- Surface type: `tooling`
- Package/source identity: `ci`
- Coverage record: `docs/documentation-coverage.csv`

## Local Commands

- `make docs-coverage` from the repository root verifies coverage for this surface.
- `make quality-pr` runs the Make-first PR quality profile from
  `scripts/ci/quality-gates.json`.
- `make quality-list` lists registered quality profiles and gates.
- `make quality-explain CHECK=<gate-id>` explains one registered check.
- `make docker-smoke` builds the Console/image and verifies the Docker runtime
  can evaluate, persist receipts, export/verify evidence, replay-verify, and
  survive restart with a stable root key.
- `make compose-smoke` runs the same runtime checks through `docker-compose.yml`.
- `make helm-chart-smoke` renders the Kubernetes chart with a Kubernetes Helm
  binary. The local `helm` command may be the HELM OSS CLI, so set
  `KUBE_HELM_CMD` or let the script use the pinned containerized Helm runner.
- `make kind-smoke` installs the chart into kind, runs the governed-call and
  evidence/replay checks, restarts the pod, and verifies signing-key stability.
- `make release-smoke` verifies reproducible binaries, SBOM JSON, OpenVEX JSON,
  and Cosign bundles when a signed artifact tree is supplied.

## Quality Gate Tooling

`scripts/ci/quality.py` is the registry runner for HELM OSS quality profiles.
It supports profile execution, path impact filtering, Advisory gates, timeouts,
and GitHub Actions annotations. The registry lives in
`scripts/ci/quality-gates.json`; validate it with `make quality-self-test`
before changing profiles.

## Documentation Contract

Generated surface README. This file is a local ownership and validation contract, not the primary docs information architecture entry point. It covers the active tooling surface. Keep it aligned with the source path above and update `docs/documentation-coverage.csv` when ownership, interfaces, validation, or lifecycle status changes.
