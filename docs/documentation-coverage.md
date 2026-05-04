# Documentation Coverage

This file is the tracked documentation-completeness certificate for `helm-oss`.

## Standard

Coverage follows a standards-based SOTA bar:

- Diataxis: every active surface is classified as tutorial, how-to, reference, or explanation.
- Google developer documentation style: canonical docs should be clear, direct, and audience-specific.
- Docs-as-code: coverage is versioned and verified in CI/local gates.
- OpenAPI/protocol truth: API and wire-contract docs must point at live contract sources.

## Coverage Gate

Run:

```sh
python3 scripts/check_documentation_coverage.py
python3 scripts/check_documentation_truth.py
```

The machine-readable ledger is `docs/documentation-coverage.csv`. Every active app, service, package, SDK, infrastructure surface, docs site, API/protocol/schema surface, public route, edge/API handler, migration, example, source root, automation surface, and root workflow must have a canonical document or an explicit non-active exception.

## Current Certification

- Active surfaces covered: 276
- Unresolved documentation gaps: 0
- Known non-active exceptions must be explicit in `reviewer_notes` and must not appear as undated placeholder status markers.

Update this file and the CSV whenever code, routes, packages, migrations, deployment workflows, or public documentation surfaces change.
