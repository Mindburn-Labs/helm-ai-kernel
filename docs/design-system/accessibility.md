# Accessibility

The system is designed for dense operational software, not decorative dashboards.

- Icon-only controls require accessible names.
- Tooltips must be reachable by focus, not hover only.
- Command palette, drawers, tabs, tree rows, composer, citation chips, and tool calls must be keyboard reachable.
- Semantic state must always be expressed as text, not color alone.
- Tables must become labeled records below `1200px` without hiding required columns.
- Reduced-motion and forced-colors modes are first-class verification targets.

Run:

```bash
npm run test:a11y
npm run test:reduced-motion
npm run test:forced-colors
```

