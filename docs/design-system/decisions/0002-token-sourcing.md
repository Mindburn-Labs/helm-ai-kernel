# 0002 — Two-source-of-truth tokens with parity tests

## Status

Accepted — 2026-04-29.

## Context

A design system needs tokens to be reachable from two callers:

1. **CSS** — every primitive's `.css` file references `var(--helm-*)`.
2. **TypeScript** — runtime helpers (theme switching, contrast utilities,
   inline-style validation) need the same values typed and addressable
   in JS.

If we pick one source as canonical and code-gen the other, drift between
them becomes invisible — a renamed token in CSS leaves a stale TS export
that compiles but breaks at runtime.

## Decision

Both `src/styles/tokens.css` and `src/tokens/index.ts` are
**hand-authored canonical files** that mirror each other. A
**parity test** (`src/tokens/index.test.ts`) reads both files and fails
if any token name or value diverges. A code-gen step
(`scripts/generate-tokens.ts`) is available for bulk imports but is not
the primary editing path.

A future Style Dictionary integration will move both files behind a
single W3C-spec `tokens-spec/` source — but only after byte-for-byte
parity is proven (see ROADMAP "Later" lane).

## Consequences

- **+ Either side can be authored directly** — designers comfortable
  with CSS edit `tokens.css`; TS-comfortable engineers edit `index.ts`.
  Either change must update both files; the parity test catches drift.
- **+ Contrast gate** (`tokens:contrast:check`) reads the TS side and
  validates WCAG AA over a curated 20-pair table.
- **+ Tree-shaking-friendly** — consumers can import a single token by
  name without pulling the full CSS bundle.
- **−** Manual mirroring is a footgun without the parity test. The
  test must run on every PR; it does, via the verify chain.
- **−** Some token shapes (computed, derived) are awkward to author by
  hand. Style Dictionary backfill will solve this.

## References

- [packages/core/src/styles/tokens.css](../../packages/core/src/styles/tokens.css)
- [packages/core/src/tokens/index.ts](../../packages/core/src/tokens/index.ts)
- [packages/core/src/tokens/index.test.ts](../../packages/core/src/tokens/index.test.ts) — parity test
- [scripts/generate-tokens.ts](../../scripts/generate-tokens.ts) — `--check` mode for CI
- [scripts/generate-contrast-table.ts](../../scripts/generate-contrast-table.ts) — WCAG gate
