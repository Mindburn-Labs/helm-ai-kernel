# 0004 — No CSS-in-JS runtime; static `.css` + tokens

## Status

Accepted — 2026-04-29.

## Context

Modern React frontends ship with a wide spectrum of styling stacks:
plain CSS, CSS modules, vanilla-extract (build-time CSS-in-JS),
emotion / styled-components (runtime CSS-in-JS), tailwind, and so on.

The tradeoffs:

- **Runtime CSS-in-JS** (emotion, styled-components) ships the styling
  engine to the browser. Adds 10–20 KB gzipped, runs work on every
  render, and conflicts with React 19 streaming SSR + Suspense.
- **Build-time CSS-in-JS** (vanilla-extract, linaria) avoids the
  runtime cost but tightly couples the build pipeline to the styling
  abstraction. Every consumer's bundler must be configured to handle it.
- **Tailwind** is excellent for product apps but a poor fit for a
  *design system package*: utility classes leak the design language
  into every consumer's HTML, and consumers can override semantics by
  composing arbitrary utilities.
- **Static CSS + design tokens** is the lowest-overhead option: ship a
  single `dist/styles.css`, document the token contract, and let
  consumers import either the bundle or per-component subpaths.

## Decision

Ship **static, hand-authored CSS** in `packages/core/src/styles/*.css`,
bundled into a single `dist/styles.css` plus per-component CSS imports
when consumers need to opt out of the monolith. **No runtime CSS-in-JS
library is a dependency or a peer dependency.** `style={…}` inline
objects are permitted only for genuinely dynamic values
(see `tokens/index.ts:approvedDynamicInlineStyles`); a forthcoming
ESLint rule (Phase 9.B) will enforce this.

Theme switching uses **CSS custom properties** keyed off `[data-theme]`
on `<html>`. The `ThemeProvider` writes the attribute; CSS does the
rest. This keeps theme switching free of re-render churn.

## Consequences

- **+ Zero runtime cost** — the styling engine is the browser.
- **+ Clean SSR / RSC story** — no React Context required for styles
  to work in server components.
- **+ Consumer-friendly bundling** — tree-shaking works at the JS
  level; CSS is fetched once at app boot.
- **+ Trivial theme variants** — adding a new `data-theme="…"` value
  is a CSS edit; no JS rebuild.
- **−** No "pseudo-state styles co-located with component" — pseudo
  classes live in CSS files, not the React component file.
  Mitigated by per-primitive CSS organization (Phase 9.C extraction
  splits `components.css` into `components/{name}.css` files).
- **−** Class names are global. Mitigated by a `.helm-*` prefix on
  every public class.

## References

- [packages/core/src/styles/](../../packages/core/src/styles)
- [packages/core/src/styles.css](../../packages/core/src/styles.css) — barrel
- [packages/core/src/tokens/index.ts](../../packages/core/src/tokens/index.ts) → `approvedDynamicInlineStyles`
- [docs/theming.md](../theming.md) — runtime theme switching
