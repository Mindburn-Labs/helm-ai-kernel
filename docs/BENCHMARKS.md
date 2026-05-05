---
title: Benchmarks
last_reviewed: 2026-05-05
---

# Benchmarks

## Audience

## Outcome

After this page you should know what this surface is for, which source files own the behavior, which public route or adjacent page to use next, and which validation command to run before changing the claim.

## Source Truth

- Public route: `helm-oss/benchmarks`
- Source document: `helm-oss/docs/BENCHMARKS.md`
- Public manifest: `helm-oss/docs/public-docs.manifest.json`
- Source inventory: `helm-oss/docs/source-inventory.manifest.json`
- Validation: `make docs-coverage`, `make docs-truth`, and `npm run coverage:inventory` from `docs-platform`

Do not expand this page with unsupported product, SDK, deployment, compliance, or integration claims unless the inventory manifest points to code, schemas, tests, examples, or an owner doc that proves the claim.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| The public page and source behavior disagree | Treat the source path in `Source Truth` as canonical, then update the docs and source-inventory row in the same change. |
| A link or route is missing from the docs website | Check `docs/public-docs.manifest.json`, `llms.txt`, search, and the per-page Markdown export before changing navigation. |
| A claim is not backed by code or tests | Remove the claim or add the missing code, example, schema, or validation command before publishing. |

## Diagram

This scheme maps the main sections of Benchmarks in reading order.

```mermaid
flowchart LR
  Page["Benchmarks"]
  A["Targets"]
  B["What the Harness Covers"]
  C["Output"]
  D["Test-case count (referenced by pitch decks)"]
  E["Machine-readable output"]
  Page --> A
  A --> B
  B --> C
  C --> D
  D --> E
```

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
