---
title: Release and Security Evidence
last_reviewed: 2026-07-10
---

# HELM AI Kernel Release and Security Evidence

<!-- quantum_posture: this page documents release signature expectations but does not implement cryptographic controls. -->

This page collects the public release, vulnerability disclosure, supply-chain,
fuzzing, OpenSSF, VEX, SBOM, Cosign, and reproducibility material for HELM AI Kernel.

## Audience

This page is for developers installing release artifacts, security reviewers,
package maintainers, and organizations validating HELM AI Kernel before adoption.

## Outcome

You should know how a release is produced, how to verify it, where to report
vulnerabilities, and which evidence files support supply-chain review.

## Release Evidence Chain

```mermaid
flowchart TD
    subgraph Ingestion["1. Ingestion & Context Plane"]
        tag["Version tag"]
        ci["Release workflow"]
        binaries["Binaries and packages"]
        sbom["SBOM"]
        attestation["Release metadata / attestation when present"]
        optional["Optional Cosign / OpenVEX assets"]
    end

    subgraph Ledger["4. Tamper-Evident Ledger Plane"]
        verify["Artifact verification"]
    end

    %% Operational Flow Edges
    tag --> ci
    ci --> binaries
    ci --> sbom
    ci --> attestation
    ci --> optional
    binaries --> verify
    sbom --> verify
    attestation --> verify
    optional --> verify

    %% Premium Styling Rules
    style verify fill:#2f855a,stroke:#276749,stroke-width:2px,color:#fff
```


Current source release target: `v0.10.4`:
<https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.10.4>. The
release is complete only when GitHub shows Darwin/Linux/Windows binaries,
`SHA256SUMS.txt`, `sbom.json`,
`v0.10.4.openvex.json`, `release-attestation.json`, `evidence-pack.tar`,
`release.high_risk.v3.toml`, `sample-policy-material.tar`,
`helm-ai-kernel-launchpad-data.tar`, `helm-ai-kernel.mcpb`, `helm-ai-kernel.rb`,
`v0.10.4.json`, `version-status.json`, and matching `*.cosign.bundle` files for
each primary asset. Browser UI bundles are not Kernel release assets. Where a
release declares the loopback Console local-sidecar, it is a verified standalone
native closure—not a Homebrew resource or a hosted UI.

For a local Console closure, release assembly verifies the producer
bundle and exact Console source pin, signs the aggregate manifest once for the
exact Kernel tag, and compiles its SHA-256 into the Kernel binary. The Console
source tuple and producer workflow ref are immutable: the signature identity
must name the pinned `refs/tags/...` ref, which resolves to the exact source
commit. A Console `main` identity is rejected. The separate Kernel bundle is retained in the staged assets, checksum
set, standalone layout, and GitHub release; public verification derives the
exact tag from the Console manifest and does not accept a Kernel `main`
identity. Each matching
`helm-ai-kernel-<os>-<arch>-console.tar.gz` artifact contains the executable
beside the raw Console material and the host closure it will execute. Runtime
trusts that authenticated binary digest, then rechecks the installed manifest
and its source, target, archive, checksum, inventory, and provenance relations
before issuing a session or starting bundled Node. The separate producer and
Kernel Cosign bundles are release evidence; runtime requires neither host Cosign
nor network access.

## Binary SLSA provenance

The release workflow uses the upstream-supported generic generator tag
`v2.1.0`, with a preflight check that it resolves to reviewed commit
`f7dd8c54c2067bafc12ca7a55595d5ee9b75204a`. Before registry publication,
`slsa-verifier` checks the signed checksum manifest against the Kernel repository,
release tag and versioned builder. Cosign independently checks the exact builder
identity, GitHub OIDC issuer, repository, tag ref and source commit. Every file
listed by that manifest must match its checksum. A failure blocks publication.

This is the source contract for subsequent releases. The raw-SHA builder identity
on v0.10.2 is rejected by the standard verifier even though exact-identity Cosign
verification passes. Its immutable provenance is retained without backfill.

## Container image provenance

The source release workflow attests each final main and slim image digest
with signed SLSA v1 provenance. It then verifies the exact image digest,
repository, release workflow identity, tag ref, and source commit. A failed
verification blocks the release. Verified outputs are retained as `main.json`
and `slim.json` release assets; binary SLSA and BuildKit metadata cover different
subjects and do not substitute for these image attestations.

For a release produced by this workflow, use its immutable digest and commit:

```sh
gh attestation verify "oci://ghcr.io/mindburn-labs/helm-ai-kernel@${IMAGE_DIGEST}" \
  --repo Mindburn-Labs/helm-ai-kernel \
  --cert-identity "https://github.com/Mindburn-Labs/helm-ai-kernel/.github/workflows/release.yml@refs/tags/${RELEASE_TAG}" \
  --source-digest "${SOURCE_COMMIT}" --source-ref "refs/tags/${RELEASE_TAG}" \
  --predicate-type https://slsa.dev/provenance/v1
```

This is the source contract for future releases. Existing immutable releases
without the matching image attestation remain unqualified for this check;
they are not backfilled by a source change.

## Public Release Material

| Need | Source path | Public route |
| --- | --- | --- |
| Release preparation | `RELEASE.md`, `VERSION`, `CHANGELOG.md` | `/publishing`, `/changelog` |
| Vulnerability reporting | `SECURITY.md` | This page and `/publishing` |
| OpenSSF mapping | `BEST_PRACTICES.md` | This page |
| SBOM and release metadata | `release/README.md`, `scripts/ci/generate_sbom.sh`, release asset `sbom.json`, release asset `release-attestation.json` | This page |
| OpenVEX policy source | `release/vex.openvex.json`, `release/vex/policies.yaml` | This page; only claim published VEX when attached to the GitHub release |
| Cosign and reproducible binaries | `.github/workflows/release.yml`, `scripts/release/`, `docs/VERIFICATION.md` | `/verification`, `/publishing`; Cosign verification requires attached `*.cosign.bundle` files |
| Fuzzing | `oss-fuzz/`, Go fuzz tests under `core/pkg/` | This page and `/execution-security-model` |

## Verification Commands

```bash
make release-binaries-reproducible
make release-smoke
make release-assets
make verify-cosign COSIGN_ARTIFACT_DIR=./downloaded-release
make verify-fixtures
make docs-coverage docs-truth
```

Release artifacts should not be treated as trustworthy only because they are
downloaded from a release page. Verify checksums, release metadata,
receipt/evidence material, reproducible-build behavior, and signatures when
signature bundles are attached.

For tag-triggered releases, the workflow requires the tag ref to match the
checked-in `VERSION` file, requires an exact `v<version>.openvex.json`, exports
the audit EvidencePack, verifies the staged `evidence-pack.tar`, and only then
writes final checksums. A failed EvidencePack verification blocks release asset
publication.

Release EvidencePacks use the native
`07_ATTESTATIONS/evidence_pack.sig` seal. If a release is cut under the
customer or high-assurance profile, release verification must pass with
`helm-ai-kernel verify --profile customer --storage-receipt <receipt>` or the
equivalent high-assurance profile, proving the trusted external signer,
Rekor/RFC3161 anchor receipt, and active S3 Object Lock storage receipt.

For `v0.5.10`, use checksum verification, SBOM inspection, OpenVEX inspection,
release metadata inspection, offline EvidencePack verification,
reproducible-build validation, and Cosign verification against the attached
bundles.

## Historical Release Context (Signed Releases & Provenance)

Historical development releases before the `v0.5.9` release target were early
developer drafts designed to test baseline execution mechanics. Because those
iterations did not complete the current keyless Sigstore Cosign and SLSA
provenance release contract, their assets must not be treated as having
cryptographic signature bundles (`*.cosign.bundle`) or SLSA provenance
attestations unless those files are attached to the release.

Starting from a completed `v0.5.9` public release and for later tags, the
retained release pipeline must publish complete signature bundles and
attestation metadata before the release is documented as complete.

## Source Truth

- `SECURITY.md`
- `RELEASE.md`
- `BEST_PRACTICES.md`
- `release/README.md`
- `docs/PUBLISHING.md`
- `docs/VERIFICATION.md`

## Troubleshooting

| Problem | Check |
| --- | --- |
| Signature verification fails | Confirm the release actually includes `*.cosign.bundle` files, then check the expected workflow identity and Rekor entry documented in `SECURITY.md`. |
| Reproducible build hashes differ | Confirm `SOURCE_DATE_EPOCH`, `-trimpath`, and build-id settings match the release workflow. |
| VEX status is unclear | Inspect `release/vex/policies.yaml`; only rely on a release VEX file when it is attached to the GitHub release. |
| Kubernetes Helm validation runs the HELM AI Kernel CLI | Set `KUBE_HELM_CMD` to a Kubernetes Helm v3 binary or run `make helm-chart-smoke`, which uses a pinned containerized Helm runner when needed. |
| A security issue needs disclosure | Use `security@mindburn.org`; do not open a public issue. |

<!-- docs-depth-final-pass -->

## Release Verification Path

A release security page should let a developer verify an artifact without trusting prose. Include the expected version, checksum file, SBOM location, signature or provenance command, and the receipt/verifier compatibility note for that release. If a release artifact is missing, mark the verification mode as unavailable rather than implying Cosign, SBOM, or reproducible-build coverage. The minimum public acceptance path is: download release artifact, verify checksum, inspect SBOM/provenance when present, run the binary or container health check, create one receipt, and verify that receipt offline.
