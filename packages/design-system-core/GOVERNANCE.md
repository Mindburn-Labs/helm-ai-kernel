# Mindburn Labs Design System Governance (UCS 1.3)

## Core Philosophy
`@mindburn/ui-core` is the shared Mindburn UI foundation and the canonical source for HELM AI Kernel-safe primitives, base tokens, semantic state utilities, and production CSS.

Downstream products may consume the core package, but they do not become normative HELM components and they cannot define HELM AI Kernel conformance. HELM AI Kernel product truth remains bounded to this repository and its public source contracts.

Our philosophy is **Canonical Compliance**: 
- **Zero Raw HTML**: UI surfaces must be constructed exclusively from composed React primitives (e.g., `AppShell`, `Stack`, `Grid`, `Badge`).
- **Zero Raw Values**: CSS must strictly consume standard tokens. Raw `px`, `rem`, and `#hex` values are forbidden and will be blocked by CI enforcement.
- **Fail-Closed Accessibility**: Surfaces that fail WCAG 2.2 AA standards (via `axe-core`) cannot be merged.

## System Boundaries
- `@mindburn/ui-core`: HELM AI Kernel-safe primitives, layout structures, canonical base tokens, accessibility primitives, and platform-agnostic components.
- `@helm/design-system-helm`: HELM product-specific proof, policy, evidence, execution, assistant, route, state, and handoff patterns built on public core exports.
- `site-ui`: Mindburn marketing and editorial compositions built on public core exports.
- Product skins: downstream products may alias or extend core foundations for their own domain semantics, but those skins are not HELM AI Kernel conformance sources.

## Contribution Process
1. **No Local Escapes**: Shared primitives and base tokens must be elevated to the core design system before being consumed by a downstream repository. Product-domain components stay in their product layer.
2. **Review Requirement**: Any changes to `@mindburn/ui-core` require review from the Core Architecture team.
3. **Automated Enforcement**: All PRs must pass Playwright Visual Regression tests and Stylelint token enforcement.
