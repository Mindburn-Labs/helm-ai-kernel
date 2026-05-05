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
| `verify_cosign.sh` | Verifies local artifacts that have adjacent `*.cosign.bundle` files. | `make verify-cosign`, manual verification. |
| `distribute.sh` | Legacy/manual multi-package publication helper. | Manual only; do not treat as automatic release proof. |

## Validation

```bash
make release-binaries-reproducible
make sbom
make vex
bash scripts/release/verify_cosign.sh ./downloaded-release
make docs-coverage docs-truth
```

`verify_cosign.sh` exits successfully only when every bundle it finds verifies.
If a release has no `*.cosign.bundle` files, use checksums, SBOM,
release-attestation inspection, offline evidence-pack verification, and
reproducible-build validation instead.
