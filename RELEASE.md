# Release Process

<!-- quantum_posture: release process docs mention existing Cosign verification only; this page adds no post-quantum cryptographic control. -->

The retained release process is PR-first and tag-driven. `main` is protected;
prepare releases on a branch, merge only after gates pass, and tag the merged
commit.

## Current Release State

`main` declares `0.7.2`, but `v0.7.2` has neither a tag nor a GitHub Release.
The latest published GitHub release and tag is `v0.7.1`.

## Prepare v0.7.2

1. Update `VERSION`, CLI fallback version, OpenAPI `info.version`, SDK
   manifests, generated SDK comments, chart metadata, release docs, and exact
   OpenVEX with the maintained release tooling:

```bash
make prepare-version VERSION=0.7.2
make vex
```

2. Update `CHANGELOG.md` with the `v0.7.2` user-visible delta.
3. Run the maintained merge and release validation targets:

```bash
make quality-merge
make quality-release
make release-readiness
make release-assets
```

4. Confirm `dist/release-assets/` contains CLI binaries, `SHA256SUMS.txt`,
   `sbom.json`, `v0.7.2.openvex.json`, `release-attestation.json`,
   `evidence-pack.tar`, `release.high_risk.v3.toml`,
   `sample-policy-material.tar`, `helm-ai-kernel.mcpb`, and `helm-ai-kernel.rb`.
5. Confirm `./bin/helm-ai-kernel verify dist/release-assets/evidence-pack.tar` passes
   offline.

## Publish

1. Merge the release-prep PR to `main`.
2. Create the annotated `v0.7.2` tag only after the release commit is on
   `main`.
3. Push the tag and monitor the Release workflow until GitHub Release, GHCR
   images, Cosign bundles, provenance, benchmark pinning, Go SDK subdirectory
   tag publication, Homebrew formula generation, and downstream fanout finish.
4. Download the published assets into a clean directory and rerun checksum,
   Cosign, SBOM, attestation, Homebrew formula, and offline EvidencePack
   verification.
5. Run or confirm:

```bash
make version-drift-published
```

6. Commit the post-publish docs update that changes “current public release”
   references to `v0.7.2` with the actual GitHub publish timestamp.

Package publication for npm, PyPI, crates.io, and Maven-compatible consumers
requires registry credentials. If required registry credentials are absent, the
tag workflow must fail rather than documenting a partial release as complete.
