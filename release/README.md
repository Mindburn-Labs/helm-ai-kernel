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
`release-attestation.json`, `evidence-pack.tar`, and
`release.high_risk.v3.toml`.

Do not document Cosign bundle or OpenVEX files as attached to `v0.4.0`; they
were not present in the release asset list.

## Validation

```bash
make release-binaries-reproducible
make sbom
make vex
bash scripts/release/verify_cosign.sh ./downloaded-release
make docs-coverage docs-truth
```

Cosign verification requires matching `*.cosign.bundle` files in the release
directory. OpenVEX consumption requires an OpenVEX file attached to that
release.
