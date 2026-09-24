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

- `make check` is exactly what the required `ci / gate` check runs.
- `make docs-coverage` from the repository root verifies coverage for this surface.
- `make quality-pr` is a fast, path-scoped local pre-check.
- `make quality-nightly` mirrors the scheduled advisory assurance workflow.
- `make quality-release` mirrors release validation before tag publication.
- `make openapi-breaking` / `make proto-breaking` run the contract
  breaking-change gate (HELM-151 GATE 1) against the PR base branch —
  `oasdiff` for the OpenAPI surfaces, `buf breaking` for the policy-schema
  protos. The PR profile has no mutable label or environment override;
  only a source-controlled major-version bump permits a break. The release
  profile runs `make contract-breaking-release` against the commit resolved
  from the immutable prior version tag, never current `origin/main`.

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
- `ci.yml` calls `Mindburn-Labs/platform-actions` `ci.yml@v2`. Its `gate`
  job, reported as `ci / gate`, is the only required status check. It runs
  `make check` (the `merge` profile of `scripts/ci/quality-gates.json`, every
  gate blocking) after `scripts/ci/install_check_tools.sh` installs pinned
  protoc, buf, oasdiff, kind, ripgrep and the Python gate dependencies, plus a
  diff-aware dependency scan that fails only on HIGH or CRITICAL advisories a
  change introduces. It runs on every pull request, merge group and push to
  `main`, with no path filters.
- `codeql.yml` is the single CodeQL code-scanning run (Go, JavaScript and
  TypeScript, Python, Java and Kotlin). It is not required.
- `helm-integration.yml` runs the minikube Launchpad smoke when the chart or
  smoke driver changes. The positive lane spends OpenRouter tokens, so on a
  pull request it runs only with the `launchpad-live-test` label and is
  skipped otherwise; it never reports success without running. Not required.
- `lean.yml` and `tla.yml` check the Lean proof and TLA+ specs; `tee-collateral.yml`
  re-verifies the offline TEE collateral weekly. None is required.
- `claude-managed-agents-live-evidence.yml` runs the protected Daytona live
  evidence fixture for Claude Managed Agents self-hosted verification, writes a
  signed evidence pack, verifies it offline, and uploads the redacted artifacts.
  It requires the `claude-managed-agents-live` environment with
  `CLAUDE_MANAGED_AGENTS_LIVE_CONFIG_JSON` and `HELM_SIGNING_KEY_HEX` secrets.
- `dev-image.yml` is the dispatch-only, dev-grade QA lane. For one exact
  commit with a green in-repo `ci.yml` run, it publishes and signs
  `ghcr.io/mindburn-labs/helm-ai-kernel:dev-sha-<sha>`. Its signing identity is
  `dev-image.yml@refs/heads/main`, so release verification rejects it.
- `launchpad-artifacts.yml` builds and signs Launchpad OpenClaw, Hermes, and
  egress-proxy artifacts, then runs gated live local-container conformance when
  manually dispatched with the scoped CI key. Main runs retain artifact evidence
  only; an explicitly dispatched, live-conformance-backed run can attach a
  review patch, but neither this workflow nor the catalog workflow creates a
  branch or pull request.
- `launchpad-clean-install.yml` validates the published Homebrew package on a
  macOS runner, launches OpenClaw and Hermes through `local-container`, verifies
  produced EvidencePacks, and uploads redacted GA evidence.
- `nightly-quality.yml` runs advisory mutation, flake, vulnerability, runbook,
  migration, dependency hygiene, schema, and benchmark checks.
- `release.yml` calls `make quality-release` before producing binaries,
  container images, SBOM, VEX, attestations, SDK packages, signatures, and
  `version-status.json`. It runs only on `v*` tag pushes, so every keyless
  signature and SLSA attestation it creates carries the identity
  `https://github.com/Mindburn-Labs/helm-ai-kernel/.github/workflows/release.yml@refs/tags/v<version>`.
  SLSA provenance is generated only by this tag run; there is no manual
  workflow that re-attests assets already attached to a release.
- `scorecard.yml` carries only the trusted `main` and scheduled runs that
  publish Scorecard SARIF through OIDC and code-scanning authority. The
  OpenSSF results webapp rejects a publishing workflow that defines any other
  job. There is no pull-request Scorecard lane.
- `version-drift.yml` runs the published registry drift check daily and opens or
  updates one issue when any public channel falls behind `VERSION`. A channel
  that could not be read after the bounded rate-limit retries is reported as
  unknown: it does not open a drift issue and does not close an open one.

Pinned first-party setup actions should stay on Node 24-capable majors
(`checkout` v5, `setup-go` v6, `setup-python` v6, `setup-node` v6, and
`setup-java` v5). Go setup steps use `cache-dependency-path: "**/go.sum"` so
monorepo jobs do not look for a nonexistent root `go.sum`.

Tag-triggered release jobs treat the repository `VERSION` file as release
truth. The first release job fails when `GITHUB_REF_NAME` is not exactly
`v$(cat VERSION)`. Before any release publication, the preflight also requires
the tag's peeled commit to be reachable from current `origin/main` (equal to it
or one of its ancestors) and the Kernel OpenAPI
blob to exactly match `Mindburn-Labs/contracts-catalog` `main`. The workflow
never creates a downstream catalog PR; sync and merge that catalog change
before tagging. `DOWNSTREAM_FANOUT_TOKEN` is retained only as a
`contents:read` token for that preflight. Release jobs must not patch chart or
SDK package versions in CI.

Publish and signing secrets are environment secrets, never repository secrets.
Every job that reads one declares the environment that holds it:
`npm-production` (`NPM_TOKEN`), `pypi-production` (`PYPI_TOKEN`),
`crates-production` (`CRATES_TOKEN`), `maven-central` (`MAVEN_*`), and
`release-production` (`HELM_EVIDENCE_KMS_*`,
`HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_COMMAND`, `HOMEBREW_TAP_TOKEN`).
Protecting these environments (required `admins` reviewers and a `v*` tag
deployment policy) is repository configuration, tracked in HELM-732. Once it is
in place, each such job waits for approval, and the standalone `*-publish.yml`
workflows must be dispatched with `--ref v<version>`.
`scripts/ci/release_workflow_contract_test.py` fails when a job reads one of
these secrets without declaring its environment.

## Documentation Contract

Generated surface README. This file is a local ownership and validation contract, not the primary docs information architecture entry point. It covers the active CI/CD surface. Keep it aligned with the source path above and update `docs/documentation-coverage.csv` when ownership, interfaces, validation, or lifecycle status changes.
