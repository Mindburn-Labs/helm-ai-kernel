---
title: Publishing
---

# Publishing

The repository retains packaging metadata for the kernel binaries, container image, and the public SDKs.

## Package Identities

| Surface | Package Identity |
| --- | --- |
| CLI/Homebrew | `mindburnlabs/tap/helm` |
| TypeScript SDK | `@mindburn/helm` |
| Python SDK | `helm-sdk` |
| Rust SDK | `helm-sdk` |
| Java SDK | `com.github.Mindburn-Labs:helm-sdk` |
| Go SDK | module path under this repository |

## Release Inputs

Before tagging a release:

1. update `VERSION`
2. update `CHANGELOG.md`
3. run `make build`, `make test`, `make test-all`, `make crucible`
4. run `make release-binaries`, `make sbom`, and `make mcp-pack`
5. verify that SDK package versions match `VERSION`
6. verify `helm verify evidence-pack.tar` and `helm verify evidence-pack.tar --online` against the public proof API for the release pack

## Release Automation

The retained workflow set under `.github/workflows/` covers:

- main CI
- GitHub Release creation for tagged versions
- Homebrew formula generation for `mindburn/homebrew-tap`
- GHCR image publication for `latest`, version tag, and slim tag
- manual publication workflows for npm, PyPI, crates.io, and Maven-compatible distribution

Release assets must include binaries, `SHA256SUMS.txt`, SBOM, MCP bundle, release attestation, and a golden anchored EvidencePack.

If a package or channel is not represented in the retained workflow set, it should not be described as a supported public publication channel in repository documentation.
