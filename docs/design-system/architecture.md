# Architecture

HELM is split into public packages and consuming apps.

- `packages/core` owns generic tokens, state semantics, reusable primitives, layout, tables, forms, feedback, inspection views, and CSS.
- `packages/helm` owns HELM-specific products: decisions, approvals, receipts, evidence, replay, assistant contracts, route blueprints, policy utilities, fixtures, and readiness gates.
- `packages/next` owns small Next.js App Router helpers.
- `apps/workbench` documents and exercises the full system.
- `apps/next-starter` is the app handoff baseline for real website development.

Consumers must import from package roots only. Deep imports from `src`, `packages/*`, or app internals fail the quality gate.

