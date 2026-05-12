# Contributing to Mindburn Labs Design System

Thank you for your interest in improving the foundational UI architecture of Mindburn Labs. This design-system core is shared by HELM OSS and downstream products, but downstream skins do not define HELM OSS conformance.

## Getting Started
1. Ensure your Node version meets the required project standard (`>=22.22.2`).
2. Do not bypass `npm run validate` which will enforce Stylelint (blocking raw hex/px values) and Axe-Core (accessibility).

## Development Workflow
1. **Adding a Component**: Add new core React components in `src/components/` and ensure they expose deterministic props.
2. **Tokens**: Never add localized CSS variables. Ensure all colors, typography, spacing, and elevation values use canonical tokens imported from `tokens.css`.
3. **Responsive Design**: Mobile-first breakpoints must follow standard UCS 1.3 definitions.
4. **Testing**: 
   - Write tests for interactive components.
   - Run `npm run check:visual` to ensure no visual regressions across Chrome viewports.
   - Run `npm run check:axe` to ensure your additions pass WCAG 2.2 AA.

## PR Gates
Before pushing a PR, please run `/helm-pr-preflight` locally or ensure CI passes the 7-Gate Publication Audit. Breaking changes to `design-system-core` must be flagged as `needs-ultrareview`.
