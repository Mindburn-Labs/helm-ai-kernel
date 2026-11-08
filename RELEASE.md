# Release Process

<!-- quantum_posture: release process docs mention existing Cosign verification only; this page adds no post-quantum cryptographic control. -->

The retained release process is PR-first and tag-driven. `main` is protected;
prepare releases on a branch, merge only after gates pass, and tag the merged
commit.

## Execution Authority Boundary

For a code merge, follow the current `GOVERNANCE.md` contract: green required
deterministic checks on the pull request's current merge commit, with all
review threads resolved. The live `main protection` ruleset (`16024605`) is
the enforcement source; consult it rather than this release process for its
current configuration.

The distinct-provider machine interlock is release authority, not merge
authority. A code merge is still decided by the checks above. A release is
decided by the `release-permit` job of `.github/workflows/release.yml`, which
every publishing job needs:

1. It builds `release-permit-verify` (`core/cmd/release-permit-verify`) from
   the tagged commit.
2. `scripts/release/release_permit.py` binds a context to that commit: the
   merged pull request, the previous release tag as the base of the reviewed
   delta, the tree, and this workflow run. Two reviewers, pinned in
   `release/permit-reviewers.json`, each review the delta through OpenRouter
   with the existing repository secret `HELM_LAUNCHPAD_CI_OPENROUTER_API_KEY`:
   one Anthropic model and one OpenAI model.
3. `core/pkg/releasepermit` reduces the two answers to a permit. Model output
   is advisory until the reducer validates it; the permit is `ALLOW` only when
   both reviewers returned a well-formed, non-blocking `ALLOW` bound to this
   exact commit, workflow and run. The job fails on anything else. A missing
   secret, a provider error, a truncated or malformed answer, or a served
   model from the wrong provider also fails it.
4. `release-permit.json` and its context ship as GitHub Release assets;
   `release-permit-verify --verify-permit release-permit.json --context
   release-permit-context.json` re-validates them.

A `DENY` is not overridden: fix the finding on `main` and tag a new version.
Rerunning the unchanged workflow reviews the same commit again and makes a new
quorum of paid calls. One run costs roughly one quorum: the delta is capped at
600 KB per reviewer, which is on the order of a dollar or two in total at
current OpenRouter prices.

`release-rehearsal.yml` exercises the same gate on every run with recorded
answers (`release/permit-fixtures`) and makes no model call: it requires the
recorded quorum to reduce to `ALLOW` and the recorded blocking answer to
reduce to `DENY`. Release tags and package publishes still start from an
explicit maintainer action, the tag push.

## Source target

`VERSION` identifies the source release target. It is not evidence that a tag,
GitHub Release, registry package, deployment, or public claim exists. Use
`version-status.json` and `make version-drift-published` only after the
release workflow has produced those external receipts.

## Prepare a release

1. Update `VERSION`, CLI fallback version, OpenAPI `info.version`, SDK
   manifests, generated SDK comments, chart metadata, release docs, and exact
   OpenVEX with the maintained release tooling:

```bash
make prepare-version PREPARE_VERSION=<version>
make vex
```

2. Update `CHANGELOG.md` with the user-visible delta and required client
   migration notes.
3. Run the maintained merge and release validation targets:

```bash
make quality-merge
make quality-release
make release-readiness
make release-assets
```

4. Confirm `dist/release-assets/` contains CLI binaries, the five standalone
   `receipt_verify-*` verifier binaries, `SHA256SUMS.txt`,
   `sbom.json`, `v<version>.openvex.json`, `release-attestation.json`,
   `evidence-pack.tar`, `release.high_risk.v3.toml`,
   `sample-policy-material.tar`, `helm-ai-kernel.mcpb`, and `helm-ai-kernel.rb`.
5. Confirm `./bin/helm-ai-kernel verify dist/release-assets/evidence-pack.tar` passes
   offline.

## Publish

1. Merge the release-prep PR to `main`.
2. Create the annotated `v<version>` tag only after the release commit is on
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
   references to `v<version>` with the actual GitHub publish timestamp.

Package publication for npm, PyPI, crates.io, and Maven-compatible consumers
requires registry credentials. If required registry credentials are absent, the
tag workflow must fail rather than documenting a partial release as complete.
