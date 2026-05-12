# Release Tooling

Release scripts are local helpers used by Makefile targets and GitHub Actions.
They are source truth for what the repository can generate, not proof that a
specific GitHub release attached a matching asset.

## Scripts

| Script | Purpose | Caller |
| --- | --- | --- |
| `build-evidence-bundle.sh` | Builds a tarred evidence bundle and attestation JSON from an existing evidence directory. | Manual release preparation. |
| `generate_vex.sh` | Emits `release/vex/v<version>.openvex.json` from the current `sbom.json` baseline. | `make vex`, release workflow. |
| `homebrew_formula.rb` | Generates a Homebrew formula from version and checksum inputs. | release workflow. |
| `pin_benchmarks.sh` | Pins a benchmark snapshot for a release tag. | `make bench-pin`, release workflow. |
| `stage_release_assets.sh` | Stages the complete release asset directory, including EvidencePack, sample policy material, attestation, Homebrew formula, and checksums. | `make release-assets`, release workflow. |
| `verify_cosign.sh` | Verifies local artifacts that have adjacent `*.cosign.bundle` files. | `make verify-cosign`, manual verification. |
| `distribute.sh` | Legacy/manual multi-package publication helper. | Manual only; do not treat as automatic release proof. |

## Validation

```bash
make release-binaries-reproducible
make sbom
make vex
make release-assets
bash scripts/release/verify_cosign.sh ./downloaded-release
make docs-coverage docs-truth
```

`verify_cosign.sh` verifies every bundle it finds. A run with zero
`*.cosign.bundle` files proves no signature coverage; check that bundle files
exist before treating Cosign as part of a release evidence set. If a release has
no bundle files, use checksums, SBOM, release metadata inspection, offline
EvidencePack verification, and reproducible-build validation instead.
