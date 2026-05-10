# Mindburn Labs Design System Governance (UCS 1.3)

## Core Philosophy
The Mindburn Labs Design System (@helm/design-system-core) is the single, canonical source of truth for all visual and interactive surfaces across the Mindburn Labs enterprise ecosystem. This includes HELM OSS, HELM Commercial, Titan, Pilot, Mindburn Admin, and the public-facing documentation and marketing sites.

Our philosophy is **Canonical Compliance**: 
- **Zero Raw HTML**: UI surfaces must be constructed exclusively from composed React primitives (e.g., `AppShell`, `Stack`, `Grid`, `Badge`).
- **Zero Raw Values**: CSS must strictly consume standard tokens. Raw `px`, `rem`, and `#hex` values are forbidden and will be blocked by CI enforcement.
- **Fail-Closed Accessibility**: Surfaces that fail WCAG 2.2 AA standards (via `axe-core`) cannot be merged.

## System Boundaries
- `@helm/design-system-core`: Foundational UI primitives, layout structures, canonical tokens, and platform-agnostic components.
- `@helm/design-system-helm`: Commercial/Product-specific extensions built purely on top of `core`.
- `site-ui`: Marketing-specific layout structures (e.g., `LabHero`) built purely on top of `core`.

## Contribution Process
1. **No Local Escapes**: Any new design pattern must be elevated to the core design system before being consumed by a downstream repository.
2. **Review Requirement**: Any changes to `design-system-core` require review from the Core Architecture team.
3. **Automated Enforcement**: All PRs must pass Playwright Visual Regression tests and Stylelint token enforcement.
