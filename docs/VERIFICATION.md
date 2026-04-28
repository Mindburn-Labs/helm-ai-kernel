---
title: Verification
---

# Verification

The verification path is local-first. `helm verify <evidence-pack.tar|dir>` performs offline checks by default; `--online` is optional and only runs after offline checks pass.

## Offline Verification

```bash
helm verify evidence-pack.tar
```

Compatibility form:

```bash
helm verify --bundle evidence-pack.tar
```

Successful compact output includes the envelope id, signature count, anchor state, and sealed timestamp when those fields are embedded in the pack. If no anchor is embedded, the CLI reports `anchor offline`; it does not invent an anchor.

## Online Proof Check

```bash
helm verify evidence-pack.tar --online
```

`--online` posts envelope/root metadata to `HELM_LEDGER_URL` or `https://mindburn.org/api/proof/verify`. Public proof verification is additive and must never use fixture-backed positive proof.

## Export and Verify

```bash
helm export --evidence ./data/evidence --out evidence.tar
helm verify evidence.tar
```

## Cosign Artifact Verification

Every release artifact is signed via cosign keyless OIDC. Verify a
downloaded binary blob with the bundled signature:

```bash
cosign verify-blob \
  --bundle helm-linux-amd64.cosign.bundle \
  --certificate-identity-regexp "https://github.com/Mindburn-Labs/helm-oss" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  helm-linux-amd64
```

Verify the published container image:

```bash
cosign verify \
  --certificate-identity-regexp "Mindburn-Labs/helm-oss" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/mindburn-labs/helm-oss:<version>
```

Verify every artifact in a downloaded release directory in one command:

```bash
make verify-cosign DIR=./downloaded-release/
```

`make verify-cosign` walks the directory, finds every `*.cosign.bundle`,
runs `cosign verify-blob` against the matching artifact, and exits
non-zero on any failure.

### VEX Consumption

Each release ships an OpenVEX 0.2.0 document at
`release/vex/v<version>.openvex.json` next to the SBOM. Filter your
SBOM scanner output through the published VEX statements:

```bash
vexctl filter --vex release/vex/v<version>.openvex.json sbom.json
```

CVEs marked `not_affected` in the VEX are removed from the scan output;
`under_investigation` and `affected` entries pass through unchanged so
the scanner can still surface them.

## Run the Maintained Validation Targets

```bash
make test
make test-all
make crucible
```

## Benchmarks

```bash
make bench
make bench-report
```

The benchmark report writes a local artifact under `benchmarks/results/`; benchmark output is generated locally or in CI and is not committed as a release-truth artifact in the repository tree.
