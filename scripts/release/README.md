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
| `stage_release_assets.sh` | Stages the complete release asset directory, including exact tag OpenVEX, verified EvidencePack, sample policy material, attestation, Homebrew formula, and checksums. | `make release-assets`, release workflow. |
| `verify_cosign.sh` | Verifies local artifacts that have adjacent `*.cosign.bundle` files. | `make verify-cosign`, manual verification. |
| `distribute.sh` | Legacy/manual multi-package publication helper. | Manual only; do not treat as automatic release proof. |
| `check_version_drift.py` | Checks local source versions and published release channels with bounded per-surface requests. | `make version-drift`, `make version-drift-published`, scheduled monitor. |
| `check_version_drift_test.py` | Self-test for required published-channel coverage and drift-monitor error shaping. | Manual validation for release monitor edits. |

## Validation

```bash
make quality-merge
make quality-release
make release-readiness
make release-assets
bash scripts/release/verify_cosign.sh ./downloaded-release
python3 scripts/release/check_version_drift_test.py
make docs-coverage docs-truth
make version-drift-published
```

On tag builds, the Makefile derives `VERSION` from `GITHUB_REF_NAME` so the
binary version, SBOM component version, OpenVEX filename, Homebrew formula, and
release attestation all match the tag. `stage_release_assets.sh` requires the
matching OpenVEX file, generates a non-seeded release EvidencePack from release
build inputs, verifies `evidence-pack.tar`, and writes the final checksum
manifest.

`verify_cosign.sh` verifies every bundle it finds. A run with zero
`*.cosign.bundle` files proves no signature coverage; check that bundle files
exist before treating Cosign as part of a release evidence set. If a release has
no bundle files, use checksums, SBOM, release metadata inspection, offline
EvidencePack verification, and reproducible-build validation instead.
