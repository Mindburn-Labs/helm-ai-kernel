# Security Policy

<!-- quantum_posture: this policy page mentions Cosign/OIDC verification of release artifacts; it implements no cryptographic control and makes no post-quantum claim. -->

## Reporting a Vulnerability

Do not open public issues for security-sensitive reports.

- Contact: `security@mindburn.org`
- Scope: this repository, its release artifacts, and the retained SDK packages

Include a clear reproduction path, affected version, and impact summary.

## Supported Versions

Security fixes are expected on the current minor version and, when practical, the immediately preceding minor.

| Version | Supported |
| --- | --- |
| `0.10.x` | Yes |
| `0.9.x` | Best effort |
| `0.8.x` and older | No |

## Verification Material

The repository keeps:

- reproducible release-binary targets and checksum generation
- release automation that can sign artifacts when Cosign bundles are produced
  and attached
- an SBOM generation script in `scripts/ci/generate_sbom.sh`
- offline evidence verification in the `helm-ai-kernel verify` command

For release-process details, see [RELEASE.md](RELEASE.md).

## Reproducible Builds

Release binaries are built reproducibly. Run `make release-binaries-reproducible`
locally to build deterministic binaries pinned to `SOURCE_DATE_EPOCH`,
`-trimpath`, and a sealed build id. The release pipeline runs the
`reproducibility-check` job in `.github/workflows/release.yml`, which
performs the build twice on independent runners and diffs the SHA-256
set. A release tag does not publish artifacts unless that diff is empty.

## Cosign Signing Roots

Release artifacts can be verified with cosign keyless OIDC when the GitHub
release attaches matching `*.cosign.bundle` files. The trust roots are:

- **Sigstore Fulcio** — the certificate authority that issues the
  short-lived signing certificate for the GitHub Actions workflow
  identity.
- **Sigstore Rekor** — the public transparency log that records every
  signing event.

The signing identity is the GitHub Actions workflow itself
(`https://github.com/Mindburn-Labs/helm-ai-kernel/.github/workflows/release.yml@refs/tags/v*`).
Verification commands and the recovery path are documented in
[docs/VERIFICATION.md](docs/VERIFICATION.md).

Use the verification material attached to the exact version on the
[GitHub Releases page](https://github.com/Mindburn-Labs/helm-ai-kernel/releases).
Verify `SHA256SUMS.txt`, `sbom.json`, the version's `*.openvex.json`,
`release-attestation.json`, offline `evidence-pack.tar`, and matching
`*.cosign.bundle` files. A tag or a published image alone does not establish
that every release channel and verification asset completed successfully.

## Continuous Fuzzing

Continuous fuzzing is configured for upstream OSS-Fuzz under the
[`oss-fuzz/`](oss-fuzz/) directory. ClusterFuzz issues against helm-ai-kernel
are tracked publicly through the OSS-Fuzz issue tracker; the project
maintainer set is the auto-CC for new findings via the `auto_ccs` field
in `oss-fuzz/project.yaml`.
