# 0003 — `asChild` composition over polymorphic `as` prop

## Status

Accepted — 2026-04-29.

## Context

Primitives like `Button`, `Badge`, `Tooltip`, and `IconButton` need to
render as something other than their default element — most commonly an
`<a>` for links, a router `<Link>` for navigation, or a fragment-style
wrapper. Two common approaches:

1. **Polymorphic `as` prop** — `<Button as="a" href="…">`. Type-safe but
   complex generics; `as` can't reach into a router-Link's typed props
   without major helpers; bundle size grows.
2. **Slot-based `asChild`** — `<Button asChild><a href="…">…</a></Button>`.
   The primitive clones its single child and merges its className /
   data-attrs / ARIA / event handlers onto the consumer's element.

## Decision

Use the **`asChild` pattern**, copied from Radix UI:

- Each composable primitive accepts `asChild?: boolean`.
- When true, the primitive renders via the internal `Slot` component
  (`packages/core/src/components/slot.tsx`) which `cloneElement`s the
  single child, merging:
  - `className` (concatenated, primitive's own classes prepended).
  - Refs (via `mergeRefs`).
  - Event handlers (via `composeHandlers` — primitive's runs first,
    consumer's runs after).
  - `data-*` and `aria-*` attributes (consumer overrides win on collision
    only when explicit).
- The Slot, `mergeRefs`, `composeHandlers`, `mergeProps` helpers are all
  exported from the package root for consumer composition.

Currently shipped: `Button`, `IconButton`, `Badge`, `Tooltip`, `Panel`.
Roadmap: extend to overlay-trigger primitives (Dialog, Popover, Menu).

## Consequences

- **+ Native types** — `<Button asChild><Link href="…">…</Link></Button>`
  uses `Link`'s real types directly; no polymorphic generics needed.
- **+ Smaller bundle** — no per-primitive type-level branching.
- **+ Easier composition** — consumers can wrap primitives in router
  links, motion components, or any third-party element without forking.
- **−** Strict requirement: the consumer must pass exactly one child
  element. Multiple children or strings throw at dev time.
- **−** Discoverability cost: contributors must know the pattern
  exists. Mitigated by JSDoc on every `asChild` prop and the
  Slot stories in `primitives.stories.tsx`.

## References

- [packages/core/src/components/slot.tsx](../../packages/core/src/components/slot.tsx)
- [Radix UI Slot](https://www.radix-ui.com/primitives/docs/utilities/slot)
- Stories demonstrating the pattern in
  [primitives.stories.tsx](../../packages/core/src/components/primitives.stories.tsx).
