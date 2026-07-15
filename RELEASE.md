# Release Process

<!-- quantum_posture: release process docs mention existing Cosign verification only; this page adds no post-quantum cryptographic control. -->

The retained release process is PR-first and tag-driven. `main` is protected;
prepare releases on a branch, then merge only when the exact candidate passes
source-owned deterministic gates, has a distinct-provider 2-of-2 permit, and
has an exact-head approval-only App interlock. CI, reviews, labels, and human
approval are evidence for those controls, not merge authority. Private and
internal repositories remain merge-held until GitHub entitlement and the
equivalent machine interlock are live-proven.

## Current Baseline

The actual public baseline for the `v0.5.0` release is `v0.4.0`. GitHub has no
public `v0.4.1` Release object, so release notes and verification docs must not
describe `v0.4.1` as the current release.

## Prepare v0.6.0

1. Update `VERSION`, CLI fallback version, OpenAPI `info.version`, SDK
   manifests, generated SDK comments, chart metadata, release docs, and exact
   OpenVEX with the maintained release tooling:

```bash
make prepare-version VERSION=0.6.0
make vex
```

2. Update `CHANGELOG.md` with the `v0.6.0` user-visible delta.
3. Run the maintained merge and release validation targets:

```bash
make quality-merge
make quality-release
make release-readiness
make release-assets
```

Passing these targets is necessary deterministic evidence; it does not replace
the permit or exact-head App interlock.

4. Confirm `dist/release-assets/` contains CLI binaries, `SHA256SUMS.txt`,
   `sbom.json`, `v0.6.0.openvex.json`, `release-attestation.json`,
   `evidence-pack.tar`, `release.high_risk.v3.toml`,
   `sample-policy-material.tar`, `helm-ai-kernel.mcpb`, and `helm-ai-kernel.rb`.
5. Confirm `./bin/helm-ai-kernel verify dist/release-assets/evidence-pack.tar` passes
   offline.

## Publish

1. Merge the release-prep PR to `main` only through the three machine controls
   above. Do not treat a green CI run, review, or human approval as authority.
2. Create the annotated `v0.6.0` tag only after the release commit is on
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
   references to `v0.6.0` with the actual GitHub publish timestamp.

Package publication for npm, PyPI, crates.io, and Maven-compatible consumers
requires registry credentials. If required registry credentials are absent, the
tag workflow must fail rather than documenting a partial release as complete.
