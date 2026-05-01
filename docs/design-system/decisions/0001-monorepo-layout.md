# 0001 — npm-workspaces monorepo layout

## Status

Accepted — 2026-04-29.

## Context

The HELM design-system grew from a single `src/` package to multiple
related artefacts: a portable core layer (tokens + primitives), a
HELM-product layer (assistant + policy + handoff), a Next.js helper
layer, a workbench app, a docs site, and a starter app. Shipping each
as a separate repo would have multiplied release overhead, made
cross-cutting refactors painful, and broken the contrast / a11y / size
gates that depend on a single source of truth. Shipping everything as
a single non-workspaced repo would have made the public packages hard
to consume independently.

## Decision

Use **npm workspaces** with the following structure:

```
packages/
  core/      → @helm/design-system-core   (tokens, primitives, layouts)
  helm/      → @helm/design-system-helm   (assistant, policy, handoff)
  next/      → @helm/design-system-next   (Next.js App-Router helpers)
apps/
  workbench/ → @helm/workbench            (Vite SPA, integration surface)
  docs/      → @helm/docs                 (Ladle stories site)
  next-starter/ → @helm/next-starter      (consumer reference)
```

- Each `packages/*` ships as a published npm package with its own
  `exports` map.
- Each `apps/*` is a private workspace consumer that imports the
  packages by name (no relative cross-tree imports).
- The root holds shared devDeps (eslint, vitest, vite, playwright,
  size-limit) and the verify chain.

## Consequences

- **+ Cross-cutting changes** (token rename, semantic state shift)
  land in one PR, with all consumers green-tested in the same CI run.
- **+ Independent releases** are still possible via Changesets — each
  package version-bumps independently.
- **+ Tree-shake-friendly** — consumers depend on the package they
  need, not the monorepo.
- **−** Workspaces introduce npm bookkeeping (package-lock at root,
  hoisting). Lockfile churn on dependency changes is wider than a
  single-package repo.
- **−** Some tooling (TypeScript project refs, ESLint flat config)
  needs explicit workspace-aware setup.

## References

- [packages/](../../packages)
- [apps/](../../apps)
- Root [package.json](../../package.json) → `"workspaces"` field.
