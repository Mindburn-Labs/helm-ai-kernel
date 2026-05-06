# Library Adoption

This repo ships `@helm/design-system-core` as the OSS frontend contract. It does not ship a browser app, workbench, Next starter, or HELM product-specific design-system package.

## Install

This package is consumed from the repository workspace by `apps/console`.
Public npm registry publication was not verified during the 2026-05-06 OSS
readiness audit. For external consumers, use a verified release tarball or wait
for the package publication workflow to publish the package.

## Required CSS

```tsx
import "@helm/design-system-core/styles.css";
```

Core CSS owns tokens, primitive styles, providers, forms, layout, data, feedback, and inspection components.

## Supported Entrypoints

Use package roots for convenience:

```tsx
import { Button, DataTable, Dialog, FormField, TextInput } from "@helm/design-system-core";
```

Use subpaths when bundle boundaries matter:

```tsx
import { DatePicker } from "@helm/design-system-core/components/datepicker";
import { Accordion, MenuButton, Popover } from "@helm/design-system-core/components/primitives";
import { primitiveCoverage } from "@helm/design-system-core/primitives/catalog";
```

Never import from `packages/design-system-core/src`, `dist` internals, or relative workspace paths. The package smoke test typechecks public entrypoints, CSS imports, and token JSON imports.

## Composition Rules

- Build product routes from core primitives first, then add product semantics in the consuming application.
- Keep state vocabulary from `@helm/design-system-core/state`; do not invent one-off visual states.
- Keep tokens as the only source of color, spacing, typography, motion, density, and theme values.

## Consumer Verification

Before publishing or handing to an outside engineer, run:

```bash
cd packages/design-system-core
npm ci
npm run typecheck
npm test
npm run build
npm run smoke
npm run pack:dry
```

The package smoke step packs the built package, validates all exported tarball targets, imports built packages at runtime, and typechecks a temporary consumer using CSS imports, token JSON, root imports, and public subpaths.
