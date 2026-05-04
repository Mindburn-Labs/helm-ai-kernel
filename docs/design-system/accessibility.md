# Accessibility

The system is designed for dense operational software, not decorative dashboards.

- Icon-only controls require accessible names.
- Tooltips must be reachable by focus, not hover only.
- Command palette, drawers, tabs, tree rows, composer, citation chips, and tool calls must be keyboard reachable.
- Semantic state must always be expressed as text, not color alone.
- Tables must become labeled records below `1200px` without hiding required columns.
- Reduced-motion and forced-colors behavior must remain token/CSS driven so product consumers can verify it in their own browser suites.

Run:

```bash
cd packages/design-system-core
npm test
```

The OSS package currently has jsdom unit and contract coverage. Browser-level a11y, reduced-motion, forced-colors, and visual checks belong in the consuming app or in a future OSS fixture app if one is added.
