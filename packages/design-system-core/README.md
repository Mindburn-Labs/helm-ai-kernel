# @helm/design-system-core

Canonical OSS source for HELM design-system tokens, primitives, semantic state utilities, and production CSS. Commercial HELM repos may carry a synced mirror for workspace builds, but this package is the source of truth for OSS-safe core UI contracts.

Core React primitives, design tokens, semantic state utilities, and production CSS for HELM-compatible products.

## Install

This package is consumed from the workspace by the OSS Console. Public npm
registry publication was not verified during the 2026-05-06 OSS readiness
audit.

For local package validation:

```bash
npm ci
npm run build
npm run pack:dry
```

## Use

```tsx
import { Button, Dialog, FormField, TextInput, primitiveCoverage } from "@helm/design-system-core";
import "@helm/design-system-core/styles.css";

export function Example() {
  return (
    <FormField label="Policy owner" required>
      <TextInput name="owner" autoComplete="organization" />
    </FormField>
  );
}
```

## Public Entry Points

- `@helm/design-system-core`
- `@helm/design-system-core/components`
- `@helm/design-system-core/components/announce`
- `@helm/design-system-core/components/context-menu`
- `@helm/design-system-core/components/core`
- `@helm/design-system-core/components/data`
- `@helm/design-system-core/components/data-table`
- `@helm/design-system-core/components/datepicker`
- `@helm/design-system-core/components/feedback`
- `@helm/design-system-core/components/form-extensions`
- `@helm/design-system-core/components/primitives`
- `@helm/design-system-core/components/forms`
- `@helm/design-system-core/components/hover-card`
- `@helm/design-system-core/components/i18n`
- `@helm/design-system-core/components/inspect`
- `@helm/design-system-core/components/layout`
- `@helm/design-system-core/components/menubar`
- `@helm/design-system-core/components/slot`
- `@helm/design-system-core/components/status`
- `@helm/design-system-core/components/telemetry`
- `@helm/design-system-core/components/theme-provider`
- `@helm/design-system-core/state`
- `@helm/design-system-core/tokens`
- `@helm/design-system-core/primitives/catalog`
- `@helm/design-system-core/styles.css`
- `@helm/design-system-core/tokens.json`

Only these entry points are supported. Do not import from `src` or package internals.

## Verify

```bash
npm ci
npm run typecheck
npm test
npm run build
npm run smoke
npm run pack:dry
```
