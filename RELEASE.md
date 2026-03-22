# HELM Release Process

## One-Button Release

Cutting a release is fully automated. Push a tag and CI handles everything.

```bash
# 1. Update VERSION file (single source of truth)
# 2. Update CHANGELOG.md

# 3. Tag and push
VERSION=$(cat VERSION)
git tag -s "v${VERSION}" -m "HELM v${VERSION}"
git push origin "v${VERSION}"
```

That's it. The `release.yml` workflow runs on tag push and:

1. **Builds** cross-platform binaries (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64)
2. **Generates** SHA256SUMS.txt checksums
3. **Generates** CycloneDX SBOM (sbom.json)
4. **Signs** checksums with Cosign (OIDC keyless)
5. **Runs** the 10-minute smoke test (hard gate — release fails if this fails)
6. **Generates** golden artifacts (golden-evidencepack.tar, golden-run-report.html)
7. **Builds and pushes** Docker images to GHCR (`helm:<version>`, `helm:latest`, `helm:<version>-slim`)
8. **Signs** Docker images with Cosign
9. **Creates** GitHub Release with all artifacts attached
10. **Attests** build provenance (SLSA)
11. **Publishes** npm packages (@mindburn/helm, @mindburn/helm-openai-agents, @mindburn/helm-mastra, @mindburn/helm CLI)
12. **Publishes** PyPI packages (helm)
13. **Publishes** crate (helm)
14. **Publishes** Maven artifact (ai.mindburn.helm:helm)
15. **Publishes** NuGet package (if sdk/dotnet exists)
16. **Generates** compatibility matrix snapshot

## Release Artifacts (GitHub Release)

Every release MUST include:

| Artifact                    | Description                         |
| --------------------------- | ----------------------------------- |
| `helm-linux-amd64`          | Linux AMD64 binary                  |
| `helm-linux-arm64`          | Linux ARM64 binary                  |
| `helm-darwin-amd64`         | macOS Intel binary                  |
| `helm-darwin-arm64`         | macOS Apple Silicon binary          |
| `helm-windows-amd64.exe`    | Windows AMD64 binary                |
| `SHA256SUMS.txt`            | SHA-256 checksums for all binaries  |
| `SHA256SUMS.txt.sig`        | Cosign signature over checksums     |
| `sbom.json`                 | CycloneDX SBOM                      |
| `helm.mcpb`                 | Claude Desktop one-click bundle     |
| `golden-evidencepack.tar`   | Golden EvidencePack from smoke test |
| `golden-run-report.html`    | Golden Proof Report HTML            |
| `compatibility-matrix.json` | Compatibility matrix snapshot       |
| `compatibility-matrix.md`   | Human-readable compatibility matrix |

## Verification

```bash
# Verify checksums
sha256sum -c SHA256SUMS.txt

# Verify Cosign signature
cosign verify-blob --signature SHA256SUMS.txt.sig SHA256SUMS.txt

# Verify Docker image
cosign verify ghcr.io/mindburn-labs/helm-oss/helm:<version>

# Verify EvidencePack
helm verify --bundle golden-evidencepack.tar
```

## CI Workflows

| Workflow                   | Trigger                 | Purpose                                                       |
| -------------------------- | ----------------------- | ------------------------------------------------------------- |
| `ci.yml`                   | PR / push to main       | Go test, lint, conformance, adapter tests, MCPB validation    |
| `helm_core_gates.yml`      | Push to main (core/)    | Full test suite, fuzz, race, SBOM, provenance, container scan |
| `compatibility_matrix.yml` | Weekly Monday 06:00 UTC | Publish compatibility matrix artifacts                        |
| `release.yml`              | Tag `v*`                | Full release pipeline (builds, tests, publishes)              |

## Versioning

- **Semver** for CLI and SDK packages
- **Receipt schema version**: pinned in each receipt, bumped on schema changes
- **ProofGraph schema**: versioned independently (currently `1.0`)
- **EvidencePack format**: versioned in manifest (`pack_version`)
