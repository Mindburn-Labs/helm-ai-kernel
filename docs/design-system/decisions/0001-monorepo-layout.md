# 0001 — OSS design-system package layout

## Status

Accepted — 2026-04-29.

## Context

The OSS repository needs to expose the reusable HELM design-system core without pulling in commercial product apps or private HELM-specific route packages. The package must be independently buildable, testable, packable, and consumable from this checkout.

## Decision

Use a **package-local npm package** with this structure:

```
packages/
  design-system-core/ → @mindburn/ui-core
```

- The package owns its `package.json`, `package-lock.json`, TypeScript config, test config, build scripts, smoke checks, and publishable `exports` map.
- No OSS app imports from package internals because no OSS browser app is shipped.
- Commercial apps may consume the published package or mirror it, but they are outside this repository.

## Consequences

- **+ Self-contained OSS verification** — contributors can run the package checks without a root Node workspace.
- **+ Publishable artifact** — `npm pack --dry-run` reflects the real package contents and public entrypoints.
- **+ Clear boundary** — commercial-only helpers, workbench apps, and product route packages are not implied by OSS docs.
- **−** Commercial consumers need their own browser-level integration and visual checks.

## References

- [packages/design-system-core/](../../../packages/design-system-core)
- Package [package.json](../../../packages/design-system-core/package.json) → package exports and scripts.
