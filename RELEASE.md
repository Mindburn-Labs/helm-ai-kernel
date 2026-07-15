# Release Process

<!-- quantum_posture: release process docs mention existing Cosign verification only; this page adds no post-quantum cryptographic control. -->

The retained release process is PR-first and tag-driven. `main` is protected;
prepare releases on a branch, merge only after gates pass, and tag the merged
commit.

## Current Release State

Git tag `v0.7.2` resolves to `586a5d62239fee43d5e0b251674644ac8a90fc8a`,
and GitHub published the `v0.7.2` Release with 34 attached assets at
`2026-07-14T14:40:01Z`.

That provider state is not full lockstep-release acceptance. Release run
`29338793179` failed in its Homebrew job, and the post-release version-drift
job was skipped. Homebrew PR 17 later merged the formula, but its exact-head
autonomous permit failed. Treat the GitHub tag, Release object, attached
assets, registry jobs, Homebrew state, and post-release verification as
separate evidence surfaces.

## Prepare the next release

1. Update `VERSION`, CLI fallback version, OpenAPI `info.version`, SDK
   manifests, generated SDK comments, chart metadata, release docs, and exact
   OpenVEX with the maintained release tooling:

```bash
NEXT_VERSION=x.y.z
make prepare-version VERSION="${NEXT_VERSION}"
make vex
```

2. Update `CHANGELOG.md` with the `v${NEXT_VERSION}` user-visible delta.
3. Run the maintained merge and release validation targets:

```bash
make quality-merge
make quality-release
make release-readiness
make release-assets
```

4. Confirm `dist/release-assets/` contains CLI binaries, `SHA256SUMS.txt`,
   `sbom.json`, `v${NEXT_VERSION}.openvex.json`, `release-attestation.json`,
   `evidence-pack.tar`, `release.high_risk.v3.toml`,
   `sample-policy-material.tar`, `helm-ai-kernel.mcpb`, and `helm-ai-kernel.rb`.
5. Confirm `./bin/helm-ai-kernel verify dist/release-assets/evidence-pack.tar` passes
   offline.

## Publish

1. Merge the release-prep PR to `main`.
2. Create the annotated `v${NEXT_VERSION}` tag only after the release commit is on
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
   references to `v${NEXT_VERSION}` with the actual GitHub publish timestamp
   and records any failed or skipped lockstep jobs.

Package publication for npm, PyPI, crates.io, and Maven-compatible consumers
requires registry credentials. If required registry credentials are absent, the
tag workflow must fail rather than documenting a partial release as complete.
