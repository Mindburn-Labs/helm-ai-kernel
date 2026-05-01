# @helm/design-system-core

Canonical OSS source for HELM design-system tokens, primitives, semantic state utilities, and production CSS. Commercial HELM repos may carry a synced mirror for workspace builds, but this package is the source of truth for OSS-safe core UI contracts.

Core React primitives, design tokens, semantic state utilities, and production CSS for HELM-compatible products.

## Install

```bash
npm install @helm/design-system-core react react-dom
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
- `@helm/design-system-core/components/primitives`
- `@helm/design-system-core/components/forms`
- `@helm/design-system-core/components/status`
- `@helm/design-system-core/state`
- `@helm/design-system-core/tokens`
- `@helm/design-system-core/primitives/catalog`
- `@helm/design-system-core/styles.css`
- `@helm/design-system-core/tokens.json`

Only these entry points are supported. Do not import from `src` or package internals.
