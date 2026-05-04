# 0005 — Locale defaults & RTL detection

## Status

Accepted — 2026-04-29.

## Context

The system needs to handle internationalization without locking
consumers into a heavy i18n framework. Three things have to be true:

1. **Locale resolution** — components that render dates, numbers, or
   relative time must use the consumer's chosen locale.
2. **Direction (LTR / RTL)** — the document's `dir` attribute drives
   logical CSS properties; getting this wrong breaks `inset-inline-*`,
   `padding-inline-*`, etc.
3. **Message catalogs** — eventually we may want translated strings
   embedded in the system's own UI (empty states, button labels,
   error messages).

The full FormatJS / i18next / react-intl stacks are all valid, but
each adds a 30 KB+ runtime, ICU MessageFormat parsing, and a learning
curve that isn't justified for a design-system package.

## Decision

Ship a **lightweight `I18nProvider`** in `packages/design-system-core` that:

- Stores the active **locale** (BCP-47 string) and a derived
  **direction** (`"ltr"` | `"rtl"`).
- Detects RTL by language prefix (`ar`, `fa`, `he`, `ur`, `ps`, `sd`,
  `yi`); everything else is LTR.
- Mirrors `lang` and `dir` to `document.documentElement` so logical
  CSS resolves correctly.
- Provides cached `Intl.NumberFormat`, `Intl.DateTimeFormat`,
  `Intl.RelativeTimeFormat`, and `Intl.ListFormat` instances per
  locale, plus `useFormatNumber`, `useFormatDate`,
  `useFormatRelativeTime` convenience hooks.
- Accepts a flat `messages` catalog (`Record<string, string>`) with
  `{placeholder}` interpolation. **No ICU MessageFormat parsing.**
- Outside the provider, hooks degrade to sensible defaults
  (`navigator.language`, ISO date format) rather than throw.

Consumers needing full ICU plurals, gender, or remote-loaded
catalogs can swap the provider for FormatJS without changing
component code — the Intl helpers' return types are compatible.

## Consequences

- **+ Tiny runtime** — `I18nProvider` is < 2 KB gz; no parser dep.
- **+ RTL works "for free"** — logical CSS properties + auto `dir`
  attribute means consumers don't need to special-case Arabic / Hebrew
  layouts.
- **+ Cached formatters** — `Intl.*` constructors are expensive; we
  build them once per locale.
- **−** No plural / gender / select forms. Consumers needing these
  swap to FormatJS. The system itself doesn't ship strings that need
  plural rules today (empty states, button labels are minimal nouns).
- **−** RTL detection is by language prefix, not by Unicode locale
  extension (`u-rg`). Acceptable trade-off; full BCP-47 parsing
  would add complexity for a niche edge case.

## References

- [packages/design-system-core/src/components/i18n.tsx](../../../packages/design-system-core/src/components/i18n.tsx)
- [packages/design-system-core/src/components/i18n.test.tsx](../../../packages/design-system-core/src/components/i18n.test.tsx)
- [packages/design-system-core/src/components/i18n.stories.tsx](../../../packages/design-system-core/src/components/i18n.stories.tsx)
- [docs/accessibility.md](../accessibility.md) — RTL + logical CSS
