# Canonical UI System

Mindburn UI is governed as one parent-company platform with product-specific layers. `helm-ai-kernel/packages/design-system-core` currently hosts `@mindburn/ui-core`, the canonical source for shared primitives, base tokens, semantic state utilities, accessibility primitives, and production CSS.

Sibling and portfolio repositories may consume this foundation, but they do not define HELM conformance. HELM-specific proof, policy, evidence, execution, assistant, route, state, and handoff patterns live in the commercial product layer. Mindburn marketing, docs, and Titan are consumers or skins.

## Layers

| Layer | Path | Authority |
| --- | --- | --- |
| Mindburn Core UI foundation | `helm-ai-kernel/packages/design-system-core` | Canonical shared primitives and tokens for Mindburn products |
| HELM product layer | `helm/packages/design-system-helm` | HELM domain components and patterns |
| Commercial Console | `helm/apps/console` | Consumer of core plus HELM product layer |
| Mindburn site UI | `mindburn/src/components/site-ui` | Brand, marketing, editorial, and diagram compositions |
| Docs platform | `docs-platform/packages/site` | Docs shell mapped to core tokens |
| Titan skin | `titan/apps/titan-console/src/styles/titan-tokens.css` | Titan-only domain accents and trading states |

## Package Rules

Supported core interfaces are:

- `@mindburn/ui-core`
- `@mindburn/ui-core/styles.css`
- `@mindburn/ui-core/tokens`
- `@mindburn/ui-core/tokens.json`

Supported HELM product interfaces are:

- `@helm/design-system-helm`
- `@helm/design-system-helm/styles.css`

`@helm/design-system-helm` must not re-export `@mindburn/ui-core`. Consumers import primitives from core and HELM domain components from the product package.

`@helm/design-system-core` and `@helm/design-tokens` are deprecated for one migration window. Core owns the legacy `--helm-*`, `--color-*`, `--space-*`, `--radius-*`, `--shadow-*`, motion, layout, and state aliases needed by existing usage. New code must use `@mindburn/ui-core` exports and CSS.

## Figma

Figma mirrors implementation; it is not an implementation source of truth. The governed libraries are:

- Mindburn Brand Foundations
- Mindburn Core UI Library
- HELM Product Patterns
- Titan Product Skin

Code Connect mappings live next to the corresponding implementation package so component names, props, and import paths stay grounded in repository exports.
