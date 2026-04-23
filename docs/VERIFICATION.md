---
title: Verification
---

# Verification

The verification path in the retained OSS repo is command-driven and local-first.

## Build and Run

```bash
make build
./bin/helm onboard --yes
./bin/helm demo organization --template starter --provider mock
```

## Export and Verify

```bash
./bin/helm export --evidence ./data/evidence --out evidence.tar
./bin/helm verify --bundle evidence.tar
```

## Check the Fixture Roots

```bash
make verify-fixtures
```

This validates the tracked fixture roots against the verifier used by the JavaScript CLI package.

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
