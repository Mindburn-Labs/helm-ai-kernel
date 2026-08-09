# Release Evidence

<!-- quantum_posture: this page documents release signature assets but does not implement cryptographic controls. -->

The `release/` directory stores retained release evidence inputs and policy
files. It is not a complete copy of any GitHub release.

## Files

| Path | Purpose |
| --- | --- |
| `vex.openvex.json` | Baseline OpenVEX document kept in-tree for policy review. |
| `vex/policies.yaml` | Maintainer policy file consumed by `scripts/release/generate_vex.sh`. |
| `version-surfaces.yaml` | Version-surface contract consumed by `make prepare-version` and `check_version_drift.py`; every in-tree version claim (SDK manifests, docs, `mcp-bundle.json`) must be listed here. |

## Current Release Target

The current source release target is `v0.8.3`. Its expected visible release
assets are platform binaries for Darwin, Linux, and Windows,
`helm-ai-kernel.mcpb`, `helm-ai-kernel.rb`, `SHA256SUMS.txt`, `sbom.json`,
`v0.8.3.openvex.json`, `release-attestation.json`, `evidence-pack.tar`,
`release.high_risk.v3.toml`, `sample-policy-material.tar`,
`helm-ai-kernel-launchpad-data.tar`, `multiple.intoto.jsonl`, and matching
`*.cosign.bundle` files for every primary asset.

There is no public GitHub Release object for `v0.4.1`; the actual public
baseline for the `v0.5.0` delta is `v0.4.0`.

## v0.8.3 Asset Contract

`make release-assets` stages the `v0.8.3` asset set under
`dist/release-assets/`, and the release workflow must attach that set to the
GitHub release before publication is claimed:

- five CLI binaries
- `SHA256SUMS.txt`
- `sbom.json`
- `v0.8.3.openvex.json`
- `release-attestation.json`
- `evidence-pack.tar`
- `release.high_risk.v3.toml`
- `sample-policy-material.tar`
- `helm-ai-kernel-launchpad-data.tar`
- `helm-ai-kernel.mcpb`
- `helm-ai-kernel.rb`
- `multiple.intoto.jsonl`

The sample policy material archive contains `release.high_risk.v3.toml` and
`reference_packs/eu_ai_act_high_risk.v1.json`. The GitHub release workflow
attaches `*.cosign.bundle` files generated for each primary asset.

Homebrew remains headless: it downloads only the Kernel binary and Launchpad
data. Browser UI assets are not Kernel release assets. Where a release
declares the loopback Console local-sidecar, it is a verified standalone native
closure—not a Homebrew resource or a hosted UI.

For v0.8.0, the signed Console aggregate manifest is source-pinned and its
SHA-256 is compiled into every standalone Kernel binary before release staging.
Each `helm-ai-kernel-<os>-<arch>-console.tar.gz` asset contains that binary
alongside the exact `console/` layout: both manifest bundles, all raw native
target assets, and the matching extracted closure. The local launcher must
match the compiled manifest digest and recheck the archive, checksum, inventory,
provenance, source, and target relations before it issues a session or executes
the bundled Node runtime. No host Cosign installation or network call is
required at runtime.

The source tuple is immutable; the Console producer signature remains a
protected-branch `main` workflow trust assumption rather than an immutable
workflow revision. A separate Kernel bundle binds that exact manifest to the
public Kernel tag, is generated once before staging, and remains in the
standalone layout, checksum set, and GitHub release. Verification derives that
exact tag from the Console manifest: `make verify-cosign COSIGN_ARTIFACT_DIR=./downloaded-release`.

## Validation

```bash
make quality-merge
make quality-release
make release-readiness
make release-assets
make verify-cosign COSIGN_ARTIFACT_DIR=./downloaded-release
make docs-coverage docs-truth
make version-drift-published
```

For tag-triggered release jobs, `make release-assets` uses the tag version,
requires the matching `release/vex/v<version>.openvex.json`, verifies the
staged `evidence-pack.tar`, and fails before checksum publication if any
indexed EvidencePack file is missing.

Cosign verification requires matching `*.cosign.bundle` files in the release
directory. OpenVEX consumption requires an OpenVEX file attached to that
release.
