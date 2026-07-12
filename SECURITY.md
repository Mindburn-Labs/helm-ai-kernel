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
| `0.5.x` | Yes |
| `0.4.x` | Yes |
| `0.3.x` | Best effort |
| Older | No |

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

The current public GitHub release and tag is `v0.7.1`. `main` declares
`0.7.2`, but `v0.7.2` is not tagged or published. Verify only the assets
attached to the `v0.7.1` GitHub Release. After a future `v0.7.2` publication,
update this paragraph with its actual assets and GitHub publish timestamp.

## Continuous Fuzzing

Continuous fuzzing is configured for upstream OSS-Fuzz under the
[`oss-fuzz/`](oss-fuzz/) directory. ClusterFuzz issues against helm-ai-kernel
are tracked publicly through the OSS-Fuzz issue tracker; the project
maintainer set is the auto-CC for new findings via the `auto_ccs` field
in `oss-fuzz/project.yaml`.
