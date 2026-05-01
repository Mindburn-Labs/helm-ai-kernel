# Theming

Import one CSS entrypoint:

```ts
import "@helm/design-system-helm/styles.css";
```

Set theme and density on the root document:

```tsx
<html data-theme="dark" data-density="compact">
```

Next.js consumers can use:

```ts
import { helmHtmlAttributes } from "@helm/design-system-next";
```

Token rules:

- `packages/core/src/tokens/source.ts` is the canonical structured token source.
- `packages/core/src/tokens/tokens.json` is generated with `npm run tokens:generate`.
- `packages/core/src/styles/tokens.css` is the runtime CSS variable contract and is parity-tested against TypeScript tokens.
- Do not hard-code colors outside token files.

