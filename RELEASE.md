# Release Process

The retained release process is PR-first and tag-driven. `main` is protected;
prepare releases on a branch, merge only after gates pass, and tag the merged
commit.

## Current Baseline

The actual public baseline for the `v0.5.0` release is `v0.4.0`. GitHub has no
public `v0.4.1` Release object, so release notes and verification docs must not
describe `v0.4.1` as the current release.

## Prepare v0.5.0

1. Update `VERSION`, CLI fallback version, OpenAPI `info.version`, SDK
   manifests, generated SDK comments, chart metadata, and Console visible
   version.
2. Update `CHANGELOG.md` with the `v0.5.0` user-visible delta.
3. Run the maintained validation targets:

```bash
make test
make test-console
make test-platform
make test-all
make crucible
make launch-smoke
```

4. Run the release artifact target:

```bash
make release-assets
```

5. Confirm `dist/release-assets/` contains CLI binaries, `SHA256SUMS.txt`,
   `sbom.json`, `v0.5.0.openvex.json`, `release-attestation.json`,
   `evidence-pack.tar`, `release.high_risk.v3.toml`,
   `sample-policy-material.tar`, `helm.mcpb`, and `helm.rb`.
6. Confirm `./bin/helm verify dist/release-assets/evidence-pack.tar` passes
   offline.

## Publish

1. Merge the release-prep PR to `main`.
2. Replace the stale annotated `v0.5.0` tag only after the corrected release
   commit is on `main`.
3. Push the tag and monitor the Release workflow until GitHub Release, GHCR
   images, Cosign bundles, provenance, benchmark pinning, and Homebrew formula
   generation finish.
4. Download the published assets into a clean directory and rerun checksum,
   Cosign, SBOM, attestation, Homebrew formula, and offline EvidencePack
   verification.
5. Commit the post-publish docs update that changes “current public release”
   references to `v0.5.0` with the actual GitHub publish timestamp.

Package publication for npm, PyPI, crates.io, and Maven-compatible consumers
requires registry credentials. If the credentials are absent, those channels are
not published for the release and must be marked as not published.
