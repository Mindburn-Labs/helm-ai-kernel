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

- signed release binaries and checksums via release automation
- an SBOM generation script in `scripts/ci/generate_sbom.sh`
- offline evidence verification in the `helm verify` command

For release-process details, see [RELEASE.md](RELEASE.md).
