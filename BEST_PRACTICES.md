# OpenSSF Best Practices: Gold-Tier Mapping

This document maps the OpenSSF Best Practices Badge gold-tier criteria
(<https://www.bestpractices.dev/criteria/2>) to evidence in this repository.
Each criterion lists the file, CI workflow, or policy that satisfies it. Items
not yet satisfied are listed as known gaps with an owner and tracking issue.

helm-oss already holds passing-tier and silver-tier criteria via the
underlying CI hygiene; this file enumerates the gold-tier delta.

## Basics

- **Project website / repository / contribution / license / documentation**
  satisfied by `README.md`, `CONTRIBUTING.md`, `LICENSE` (Apache-2.0), and
  `docs/`.
- **Release notes** — `CHANGELOG.md` and tag-driven `.github/workflows/release.yml`.
- **Vulnerability disclosure process** — `SECURITY.md` (`security@mindburn.org`).

## Change Control

- **Public version-controlled source repository** — GitHub
  `Mindburn-Labs/helm-oss`, tracked in `.git`.
- **Unique version numbering** — `VERSION` file and tag-driven release flow
  documented in `RELEASE.md`.
- **Release notes are documented** — `CHANGELOG.md` plus the
  `softprops/action-gh-release` step in `.github/workflows/release.yml`.

## Reporting

- **Bug-reporting process** — `CONTRIBUTING.md` plus GitHub Issues.
- **Vulnerability report acknowledgement under 14 days** — `SECURITY.md` plus
  the `security@mindburn.org` mailbox.
- **No unpatched vulnerabilities of medium or higher severity for over 60 days**
  — tracked through `release/vex/policies.yaml` and the per-release
  OpenVEX statements emitted by `scripts/release/generate_vex.sh`.

## Quality

- **Working build system** — `Makefile`, `make build`.
- **Automated test suite** — `make test`, `make test-all`, and `make crucible`,
  exercised by `.github/workflows/ci.yml`.
- **New functionality has tests** — enforced by reviewer expectation in
  `CONTRIBUTING.md` and by the `kernel` job in `ci.yml`.
- **Continuous integration** — `.github/workflows/ci.yml` runs on every
  pull request and every push to `main`.
- **Static analysis** — `make lint` (`go vet`, `gofmt`) plus the linting
  step in `ci.yml`.
- **Dynamic analysis (fuzzing)** — Go native fuzz tests in
  `core/pkg/canonicalize/jcs_fuzz_test.go`,
  `core/pkg/crypto/keyring_fuzz_test.go`,
  `core/pkg/guardian/decision_fuzz_test.go`, and seven sibling packages.
  Continuous fuzzing via OSS-Fuzz is configured in `oss-fuzz/`.
- **Formal methods** — TLA+ specs in `proofs/` (`GuardianPipeline.tla`,
  `DelegationModel.tla`, `TenantIsolation.tla`, `ProofGraphConsistency.tla`,
  `CSNFDeterminism.tla`, `TrustPropagation.tla`).
- **Chaos / resilience drills** — `core/pkg/guardian/chaos_test.go`,
  `core/pkg/firewall/chaos_test.go`, `core/pkg/crypto/chaos_test.go`,
  `core/pkg/evidencepack/chaos_test.go`.

## Security

- **Knowledge of secure development** — `docs/EXECUTION_SECURITY_MODEL.md` and
  `docs/OWASP_MCP_THREAT_MAPPING.md`.
- **Use of basic good cryptographic practices** — Ed25519, ML-DSA-65, and
  hybrid signers under `core/pkg/crypto/`.
- **Secure delivery against MITM** — Cosign keyless signing for every
  release artifact (`.github/workflows/release.yml` jobs `cosign-binaries`
  and `cosign-container`); SBOM in CycloneDX produced by
  `scripts/ci/generate_sbom.sh`; OpenVEX shipped per release via
  `scripts/release/generate_vex.sh`.
- **Reproducible build** — `make release-binaries-reproducible` plus the
  `reproducibility-check` job in `.github/workflows/release.yml`, which runs
  the build twice on independent runners and diffs the SHA-256 set.
- **Supply-chain hygiene** — pinned tool versions in `.github/workflows/`,
  per-release benchmark snapshots pinned by `scripts/release/pin_benchmarks.sh`,
  and Scorecard CI in `.github/workflows/scorecard.yml`.

## Analysis (Gold-only Additions)

- **Two-factor authentication for committers** — enforced organization-wide;
  documented in `GOVERNANCE.md`.
- **Roles documented** — `MAINTAINERS.md` and `GOVERNANCE.md`.
- **Project has at least two unaffiliated maintainers** — known gap owned by
  governance, tracked through `cncf-sandbox-application`. The current
  committer set is being extended through the CNCF Sandbox process described
  in `docs/governance/cncf-application.md`.
- **Successor / continuity plan** — covered by the CNCF Sandbox application.

## Open Items

| Criterion | Status | Tracking |
| --- | --- | --- |
| Two-or-more unaffiliated maintainers | Known gap | issue: maintainer-onboarding |
| Bug bounty programme | Known gap | issue: oss-fuzz-bounty-link |
| External cryptographic review | Known gap | issue: external-crypto-review |

The OSS-Fuzz integration in `oss-fuzz/` and the Scorecard workflow in
`.github/workflows/scorecard.yml` together close the previously-open
"continuous fuzzing" and "automated supply-chain checks" criteria.
