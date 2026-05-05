# Security Policy

## Reporting a Vulnerability

Do not open public issues for security-sensitive reports.

- Contact: `security@mindburn.org`
- Scope: this repository, its release artifacts, and the retained SDK packages

Include a clear reproduction path, affected version, and impact summary.

## Supported Versions

Security fixes are expected on the current minor version and, when practical, the immediately preceding minor.

| Version | Supported |
| --- | --- |
| `0.4.x` | Yes |
| `0.3.x` | Best effort |
| Older | No |

## Verification Material

The repository keeps:

- reproducible release-binary targets and checksum generation
- release automation that can sign artifacts when Cosign bundles are produced
  and attached
- an SBOM generation script in `scripts/ci/generate_sbom.sh`
- offline evidence verification in the `helm verify` command

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
(`https://github.com/Mindburn-Labs/helm-oss/.github/workflows/release.yml@refs/tags/v*`).
Verification commands and the recovery path are documented in
[docs/VERIFICATION.md](docs/VERIFICATION.md).

The current public GitHub release, `v0.4.0` published on 2026-04-25, does not
attach `*.cosign.bundle` or `*.openvex.json` files. For that release, use
`SHA256SUMS.txt`, `sbom.json`, `release-attestation.json`, offline
`evidence-pack.tar` verification, and reproducible-build validation.

## Continuous Fuzzing

Continuous fuzzing is configured for upstream OSS-Fuzz under the
[`oss-fuzz/`](oss-fuzz/) directory. ClusterFuzz issues against helm-oss
are tracked publicly through the OSS-Fuzz issue tracker; the project
maintainer set is the auto-CC for new findings via the `auto_ccs` field
in `oss-fuzz/project.yaml`.
