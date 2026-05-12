# Workflows
<!-- docs-generated: surface-readme -->

## Purpose

Active CI/CD, publication, documentation, scorecard, proof, and code-scanning
surface for the `helm-oss` project.

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

## Active Quality Workflows

- `ci.yml` runs the retained per-surface jobs and the Make-first
  `quality-pr` summary job.
- `nightly-quality.yml` runs advisory mutation, flake, vulnerability, runbook,
  migration, dependency hygiene, schema, and benchmark checks.
- `release.yml` calls `make quality-release` before producing binaries,
  container images, SBOM, VEX, attestations, and signatures.
- `slsa-provenance.yml` builds reproducible release binaries before generating
  provenance subjects.

## Documentation Contract

Generated surface README. This file is a local ownership and validation contract, not the primary docs information architecture entry point. It covers the active CI/CD surface. Keep it aligned with the source path above and update `docs/documentation-coverage.csv` when ownership, interfaces, validation, or lifecycle status changes.
