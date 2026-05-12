# Canonical UI System

HELM UI is governed as one platform with product-specific layers. `helm-oss/packages/design-system-core` is the canonical source for OSS-safe HELM primitives, base tokens, semantic state utilities, accessibility primitives, and production CSS.

Sibling and portfolio repositories may consume this foundation, but they do not define HELM conformance. HELM-specific proof, policy, evidence, execution, assistant, route, state, and handoff patterns live in the commercial product layer. Mindburn marketing, docs, and Titan are consumers or skins.

## Layers

| Layer | Path | Authority |
| --- | --- | --- |
| Core UI foundation | `helm-oss/packages/design-system-core` | Canonical HELM OSS-safe primitives and tokens |
| HELM product layer | `helm/packages/design-system-helm` | HELM domain components and patterns |
| Commercial Console | `helm/apps/console` | Consumer of core plus HELM product layer |
| Mindburn site UI | `mindburn/src/components/site-ui` | Brand, marketing, editorial, and diagram compositions |
| Docs platform | `docs-platform/packages/site` | Docs shell mapped to core tokens |
| Titan skin | `titan/apps/titan-console/src/styles/titan-tokens.css` | Titan-only domain accents and trading states |

## Package Rules

Supported core interfaces are:

- `@helm/design-system-core`
- `@helm/design-system-core/styles.css`
- `@helm/design-system-core/tokens`
- `@helm/design-system-core/tokens.json`

Supported HELM product interfaces are:

- `@helm/design-system-helm`
- `@helm/design-system-helm/styles.css`

`@helm/design-system-helm` must not re-export `@helm/design-system-core`. Consumers import primitives from core and HELM domain components from the product package.

`@helm/design-tokens` is deprecated for one migration window. Core owns the legacy `--color-*`, `--space-*`, `--radius-*`, `--shadow-*`, motion, layout, and state aliases needed by existing Console usage. New code must use core exports and core CSS.

## Figma

Figma mirrors implementation; it is not an implementation source of truth. The governed libraries are:

- Mindburn Brand Foundations
- HELM Core UI Library
- HELM Product Patterns
- Titan Product Skin

Code Connect mappings live next to the corresponding implementation package so component names, props, and import paths stay grounded in repository exports.
