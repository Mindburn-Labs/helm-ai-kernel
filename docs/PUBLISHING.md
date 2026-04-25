---
title: Publishing
---

# Publishing

The repository retains packaging metadata for the kernel binaries, container image, and the public SDKs.

## Package Identities

| Surface | Package Identity |
| --- | --- |
| TypeScript SDK | `@mindburn/helm` |
| Python SDK | `helm-sdk` |
| Rust SDK | `helm-sdk` |
| Java SDK | `com.github.Mindburn-Labs:helm-sdk` |
| Go SDK | module path under this repository |

## Release Inputs

Before tagging a release:

1. update `VERSION`
2. update `CHANGELOG.md`
3. run the maintained validation targets
4. verify that SDK package versions match `VERSION`

## Release Automation

The retained workflow set under `.github/workflows/` covers:

- main CI
- GitHub Release creation for tagged versions
- manual publication workflows for npm, PyPI, crates.io, and Maven-compatible distribution

If a package or channel is not represented in the retained workflow set, it should not be described as a supported public publication channel in repository documentation.
