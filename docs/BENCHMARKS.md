---
title: Benchmarks
---

# Benchmarks

The benchmark harness measures retained kernel paths locally. This page documents how to run the harness, not a frozen set of numbers.

## Targets

```bash
make bench
make bench-report
```

## What the Harness Covers

The benchmark code in `core/benchmarks/` focuses on the hot paths used by the OSS kernel, including decision evaluation, signing, and persistence-related work.

## Output

`make bench-report` writes a local JSON report under `benchmarks/results/`. That path is treated as a generated artifact, not as committed repository truth.

## Test-case count (referenced by pitch decks)

As of 2026-04-18, `helm-oss/core` ships **8,930 Go test cases**, counted via:

```bash
cd core && go test -list '.*' ./... 2>&1 | grep -c '^Test'
```

This is the number the Mindburn Labs pitch decks cite under "tests" (see `docs/ai/deck-facts.md` row `h3` in the monorepo). Rerun the command above to refresh. Any deck edit claiming a different number must update this doc and the ledger in the same pass.

## Machine-readable output

## Reproducing Results

For component-level work:

```bash
cd core
go test -bench=. -benchmem ./pkg/crypto/ ./pkg/store/ ./pkg/guardian/ ./benchmarks/
```
