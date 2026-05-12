# @mindburn/ui-core

Shared Mindburn UI foundation for design-system tokens, primitives, semantic state utilities, and production CSS. HELM OSS and downstream products may consume this package, but downstream products do not define HELM OSS conformance.

Core React primitives, design tokens, semantic state utilities, and production CSS for Mindburn products.

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
import { Button, Dialog, FormField, TextInput, primitiveCoverage } from "@mindburn/ui-core";
import "@mindburn/ui-core/styles.css";

export function Example() {
  return (
    <FormField label="Policy owner" required>
      <TextInput name="owner" autoComplete="organization" />
    </FormField>
  );
}
```

## Public Entry Points

- `@mindburn/ui-core`
- `@mindburn/ui-core/components`
- `@mindburn/ui-core/components/announce`
- `@mindburn/ui-core/components/context-menu`
- `@mindburn/ui-core/components/core`
- `@mindburn/ui-core/components/data`
- `@mindburn/ui-core/components/data-table`
- `@mindburn/ui-core/components/datepicker`
- `@mindburn/ui-core/components/feedback`
- `@mindburn/ui-core/components/form-extensions`
- `@mindburn/ui-core/components/primitives`
- `@mindburn/ui-core/components/forms`
- `@mindburn/ui-core/components/hover-card`
- `@mindburn/ui-core/components/i18n`
- `@mindburn/ui-core/components/inspect`
- `@mindburn/ui-core/components/layout`
- `@mindburn/ui-core/components/menubar`
- `@mindburn/ui-core/components/slot`
- `@mindburn/ui-core/components/status`
- `@mindburn/ui-core/components/telemetry`
- `@mindburn/ui-core/components/theme-provider`
- `@mindburn/ui-core/state`
- `@mindburn/ui-core/tokens`
- `@mindburn/ui-core/primitives/catalog`
- `@mindburn/ui-core/styles.css`
- `@mindburn/ui-core/tokens.json`

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
