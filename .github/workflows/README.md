# Workflows
<!-- docs-generated: surface-readme -->

## Purpose

Active CI/CD, publication, documentation, scorecard, proof, and code-scanning
surface for the `helm-ai-kernel` project.

## Canonical Interface

- Source path: `.github/workflows`
- Surface type: `ci-cd`
- Package/source identity: `workflows`
- Coverage record: `docs/documentation-coverage.csv`

## Local Commands

- `make docs-coverage` from the repository root verifies coverage for this surface.
- `make quality-pr` mirrors the CI summary gate for pull requests.
- `make quality-nightly` mirrors the scheduled advisory assurance workflow.
- `make quality-release` mirrors release validation before tag publication.
- `make openapi-breaking` / `make proto-breaking` run the contract
  breaking-change gate (HELM-151 GATE 1) against the PR base branch —
  `oasdiff` for the OpenAPI surfaces, `buf breaking` for the policy-schema
  protos. Both now run in the `pr` profile; a major-version bump or the
  `contract:breaking-approved` PR label is the explicit override.

## Active Quality Workflows

- `approval-ceremony.yml` runs the durable approval lifecycle against a real
  PostgreSQL service under a `NOSUPERUSER NOBYPASSRLS` runtime role. It pins
  ceremony/signing golden vectors and repeats the atomic issue/consume,
  tenant/workspace/audience isolation, signed-expiry, and tamper proofs. It also
  verifies connector release-authority schemas/vectors and repeats the
  append-only, forced-RLS PostgreSQL registry proof under least-privilege writer
  and runtime roles. The
  workflow is source-owned CI evidence; it does not by itself establish branch
  protection or GA release authority.
- `ci.yml` runs the retained per-surface jobs and the Make-first
  `quality-pr` summary job.
- `claude-managed-agents-live-evidence.yml` runs the protected Daytona live
  evidence fixture for Claude Managed Agents self-hosted verification, writes a
  signed evidence pack, verifies it offline, and uploads the redacted artifacts.
  It requires the `claude-managed-agents-live` environment with
  `CLAUDE_MANAGED_AGENTS_LIVE_CONFIG_JSON` and `HELM_SIGNING_KEY_HEX` secrets.
- `launchpad-artifacts.yml` builds and signs Launchpad OpenClaw, Hermes, and
  egress-proxy artifacts, then runs gated live local-container conformance when
  manually dispatched with the scoped CI key.
- `launchpad-clean-install.yml` validates the published Homebrew package on a
  macOS runner, launches OpenClaw and Hermes through `local-container`, verifies
  produced EvidencePacks, and uploads redacted GA evidence.
- `nightly-quality.yml` runs advisory mutation, flake, vulnerability, runbook,
  migration, dependency hygiene, schema, and benchmark checks.
- `release.yml` calls `make quality-release` before producing binaries,
  container images, SBOM, VEX, attestations, SDK packages, signatures, and
  `version-status.json`.
- `scorecard.yml` uploads OpenSSF Scorecard SARIF for `main` and pull requests;
  PR SARIF is normalized so GitHub code scanning sees the same branch-protection
  category that exists on `main`.
- `slsa-provenance.yml` is a manual repair workflow that re-attests the
  checksum-covered assets already attached to a published release. Normal tag
  releases generate SLSA provenance from `release.yml`.
- `version-drift.yml` runs the published registry drift check daily and opens or
  updates one issue when any public channel falls behind `VERSION`.

Pinned first-party setup actions should stay on Node 24-capable majors
(`checkout` v5, `setup-go` v6, `setup-python` v6, `setup-node` v6, and
`setup-java` v5). Go setup steps use `cache-dependency-path: "**/go.sum"` so
monorepo jobs do not look for a nonexistent root `go.sum`.

Tag-triggered release jobs treat the repository `VERSION` file as release
truth. The first release job fails when `GITHUB_REF_NAME` is not exactly
`v$(cat VERSION)`, and release jobs must not patch chart or SDK package
versions in CI.

## Documentation Contract

Generated surface README. This file is a local ownership and validation contract, not the primary docs information architecture entry point. It covers the active CI/CD surface. Keep it aligned with the source path above and update `docs/documentation-coverage.csv` when ownership, interfaces, validation, or lifecycle status changes.
