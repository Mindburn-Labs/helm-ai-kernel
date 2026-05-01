# Library Adoption

This repo ships publishable packages, not only a workbench SPA. Treat `apps/workbench` as documentation and `apps/next-starter` as a consumer fixture.

## Install

```bash
npm install @helm/design-system-core @helm/design-system-helm @helm/design-system-next react react-dom
```

## Required CSS

```tsx
import "@helm/design-system-core/styles.css";
import "@helm/design-system-helm/styles.css";
```

Import core CSS before HELM CSS. Core owns tokens and primitive styles. HELM owns product-specific route, policy, assistant, and proof surfaces.

## Supported Entrypoints

Use package roots for convenience:

```tsx
import { Button, Dialog, FormField, TextInput } from "@helm/design-system-core";
import { DashboardComposition, routeBlueprints } from "@helm/design-system-helm";
import { helmHtmlAttributes } from "@helm/design-system-next";
```

Use subpaths when bundle boundaries matter:

```tsx
import { Accordion, MenuButton, Popover } from "@helm/design-system-core/components/primitives";
import { primitiveCoverage } from "@helm/design-system-core/primitives/catalog";
import { MockAssistantAdapter, type AssistantAdapter } from "@helm/design-system-helm/assistant";
import { routeBlueprints } from "@helm/design-system-helm/routes";
```

Never import from `packages/*/src`, `dist` internals, or relative workspace paths. The package smoke test typechecks these public entrypoints.

## Composition Rules

- Build product routes from core primitives first, then add HELM semantics where the domain requires proof, policy, assistant, or route-specific behavior.
- Keep state vocabulary from `@helm/design-system-core/state`; do not invent one-off visual states.
- Keep assistant infrastructure behind `AssistantAdapter`; the mock adapter is demo-only.
- Keep mutating assistant tool calls gated by preview, confirmation, policy result, and audit receipt.
- Keep tokens as the only source of color, spacing, typography, motion, density, and theme values.

## Consumer Verification

Before publishing or handing to an outside engineer, run:

```bash
npm run verify
```

The package smoke step runs `npm pack --dry-run`, validates metadata and README inclusion, imports built packages at runtime, and typechecks a temporary consumer using CSS imports and public subpaths.
