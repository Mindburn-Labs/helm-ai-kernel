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
