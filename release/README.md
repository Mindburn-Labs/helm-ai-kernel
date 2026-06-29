# Release Evidence

The `release/` directory stores retained release evidence inputs and policy
files. It is not a complete copy of any GitHub release.

## Files

| Path | Purpose |
| --- | --- |
| `vex.openvex.json` | Baseline OpenVEX document kept in-tree for policy review. |
| `vex/policies.yaml` | Maintainer policy file consumed by `scripts/release/generate_vex.sh`. |

## Current Release Target

The current source release target is `v0.5.18`. Its
visible release assets are platform binaries for Darwin, Linux, and Windows,
`helm-ai-kernel.mcpb`, `helm-ai-kernel.rb`, `SHA256SUMS.txt`, `sbom.json`,
`v0.5.18.openvex.json`, `release-attestation.json`, `evidence-pack.tar`,
`release.high_risk.v3.toml`, `sample-policy-material.tar`,
`helm-ai-kernel-launchpad-data.tar`, and matching `*.cosign.bundle` files for
every primary asset.

There is no public GitHub Release object for `v0.4.1`; the actual public
baseline for the `v0.5.0` delta is `v0.4.0`.

## v0.5.18 Asset Contract

`make release-assets` stages the `v0.5.18` asset set under
`dist/release-assets/`, and the release workflow attached that set to the
GitHub release:

- five CLI binaries
- `SHA256SUMS.txt`
- `sbom.json`
- `v0.5.18.openvex.json`
- `release-attestation.json`
- `evidence-pack.tar`
- `release.high_risk.v3.toml`
- `sample-policy-material.tar`
- `helm-ai-kernel-launchpad-data.tar`
- `helm-ai-kernel.mcpb`
- `helm-ai-kernel.rb`

The sample policy material archive contains `release.high_risk.v3.toml` and
`reference_packs/eu_ai_act_high_risk.v1.json`. The GitHub release workflow
attaches `*.cosign.bundle` files generated for each primary asset.

Kernel releases are headless. Browser UI assets are not Kernel release assets
and are not installed by Homebrew.

## Validation

```bash
make release-binaries-reproducible
make sbom
make vex
make release-assets
bash scripts/release/verify_cosign.sh ./downloaded-release
make docs-coverage docs-truth
```

For tag-triggered release jobs, `make release-assets` uses the tag version,
requires the matching `release/vex/v<version>.openvex.json`, verifies the
staged `evidence-pack.tar`, and fails before checksum publication if any
indexed EvidencePack file is missing.

Cosign verification requires matching `*.cosign.bundle` files in the release
directory. OpenVEX consumption requires an OpenVEX file attached to that
release.
