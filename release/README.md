# Release Evidence

The `release/` directory stores retained release evidence inputs and policy
files. It is not a complete copy of any GitHub release.

## Files

| Path | Purpose |
| --- | --- |
| `vex.openvex.json` | Baseline OpenVEX document kept in-tree for policy review. |
| `vex/policies.yaml` | Maintainer policy file consumed by `scripts/release/generate_vex.sh`. |

## Current Public Release

The current public GitHub release is `v0.4.0`, published on 2026-04-25. Its
visible release assets are platform binaries for Darwin, Linux, and Windows,
`helm.mcpb`, `helm.rb`, `SHA256SUMS.txt`, `sbom.json`,
`release-attestation.json` metadata, `evidence-pack.tar`, and
`release.high_risk.v3.toml`.

Do not document Cosign bundle or OpenVEX files as attached to `v0.4.0`; they
were not present in the release asset list.

There is no public GitHub Release object for `v0.4.1`; the actual public
baseline for the `v0.5.0` delta is `v0.4.0`.

## v0.5.0 Asset Contract

`make release-assets` stages the `v0.5.0` asset set under
`dist/release-assets/`:

- five CLI binaries
- `SHA256SUMS.txt`
- `sbom.json`
- `v0.5.0.openvex.json`
- `release-attestation.json`
- `evidence-pack.tar`
- `release.high_risk.v3.toml`
- `sample-policy-material.tar`
- `helm.mcpb`
- `helm.rb`

The sample policy material archive contains `release.high_risk.v3.toml` and
`reference_packs/eu_ai_act_high_risk.v1.json`. The GitHub release workflow
attaches `*.cosign.bundle` files generated for each primary asset.

## Validation

```bash
make release-binaries-reproducible
make sbom
make vex
make release-assets
bash scripts/release/verify_cosign.sh ./downloaded-release
make docs-coverage docs-truth
```

Cosign verification requires matching `*.cosign.bundle` files in the release
directory. OpenVEX consumption requires an OpenVEX file attached to that
release.
