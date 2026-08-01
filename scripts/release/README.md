# Release Tooling

<!-- quantum_posture: release tooling docs mention signatures and bundles but
do not implement cryptographic controls. -->

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
| `console_local_sidecar.py` | Resolves an exact Console source pin, verifies its signed aggregate manifest and each native closure, then stages the verified files. | Kernel tag release only. |
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

`VERSION` is source-controlled release truth. A tag build first proves that
`GITHUB_REF_NAME` equals `v$(VERSION)`; `stage_release_assets.sh` then rejects
both a source-version mismatch and a built CLI whose displayed version differs
from that tag. It also requires the matching OpenVEX file, generates a
non-seeded release EvidencePack from release build inputs, verifies
`evidence-pack.tar`, and writes the final checksum manifest.

The local Console browser sidecar is a standalone-release asset, never a
Homebrew resource. A tag release first dispatches the Console's native closure
builder from a checked-in exact source pin. `console_local_sidecar.py` requires
the Console keyless manifest signature, all four native targets, archive and
inventory integrity, and source/provenance agreement before the files enter
`dist/release-assets/`. The Kernel release signs that manifest for its exact
tag before staging the closure and adds a separate Kernel signature without
rewriting the producer bundle. The Console producer bundle remains alongside a separate
`*.kernel.cosign.bundle` so neither signature overwrites the other.

Before building any v0.8.0 release binary, the workflow re-verifies the signed
Console input and passes the aggregate manifest SHA-256 through
`CONSOLE_LOCAL_SIDECAR_MANIFEST_SHA256` to both normal and reproducible linker
flags as `main.consoleLocalSidecarManifestSHA256`. The local launcher uses that
compiled digest as its trust root: it must match manifest bytes and verify the
manifest's pinned source, host target, archive, checksum, inventory, and
provenance relations before creating a session or executing bundled Node. This
runtime path needs neither host `cosign` nor network access; the producer and
Kernel Cosign bundles remain release-assembly and audit evidence.

Each matching `helm-ai-kernel-<os>-<arch>-console.tar.gz` release asset
deterministically extracts to this runnable layout:

```text
<executable-dir>/
  helm-ai-kernel
  console/
    helm-console-local-sidecar-release-manifest.json
    helm-console-local-sidecar-release-manifest.json.cosign.bundle
    helm-console-local-sidecar-release-manifest.json.kernel.cosign.bundle
    helm-console-local-sidecar-<os>-<arch>.tar.gz
    helm-console-local-sidecar-<os>-<arch>.tar.gz.sha256
    helm-console-local-sidecar-<os>-<arch>.tar.gz.inventory.sha256
    helm-console-local-sidecar-<os>-<arch>.tar.gz.provenance.json
    helm-console-local-sidecar-<os>-<arch>/
```

All four target sets of raw evidence remain in `console/`; only the host target
is extracted there. Homebrew never installs this directory.

The Makefile uses `SOURCE_DATE_EPOCH` for reproducible binary builds, defaulting
to the current `HEAD` commit timestamp unless overridden. For `make vex`, an
explicit `SOURCE_DATE_EPOCH` override still wins; otherwise the Makefile reuses
the timestamp already checked into `release/vex/v$(VERSION).openvex.json` and
falls back to `HEAD` only when that exact VEX file does not exist yet. That
keeps squash-merged release commits from rewriting tracked OpenVEX timestamps
while preserving intentional artifact reproduction overrides.

`verify_cosign.sh` verifies every bundle it finds. A run with zero
`*.cosign.bundle` files proves no signature coverage; check that bundle files
exist before treating Cosign as part of a release evidence set. If a release has
no bundle files, use checksums, SBOM, release metadata inspection, offline
EvidencePack verification, and reproducible-build validation instead.
