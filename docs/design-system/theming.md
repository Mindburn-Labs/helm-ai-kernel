# Theming

Import one CSS entrypoint:

```ts
import "@mindburn/ui-core/styles.css";
```

Set theme and density on the root document:

```tsx
<html data-theme="dark" data-density="compact">
```

React consumers can also use `ThemeProvider` to write `data-theme` and `data-density` onto `document.documentElement`.

Token rules:

- `packages/design-system-core/src/tokens/source.ts` is the canonical structured token source.
- `packages/design-system-core/src/tokens/tokens.json` mirrors the public JSON token contract.
- `packages/design-system-core/src/styles/tokens.css` is the runtime CSS variable contract and is parity-tested against TypeScript tokens.
- Do not hard-code colors outside token files.
