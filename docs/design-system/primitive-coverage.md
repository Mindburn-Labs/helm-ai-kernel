# Primitive Coverage

The core package is intended to cover the same adoption surface an engineer expects from Radix, Ariakit, or Geist: actions, overlays, disclosure, navigation, forms, status, layout, collections, and feedback.

The canonical machine-readable coverage list is exported from:

```ts
import { primitiveCoverage, primitiveCoverageSummary } from "@helm/design-system-core/primitives/catalog";
```

## Stable Coverage

| Area | Stable primitives |
| --- | --- |
| Action | `Button`, `IconButton`, `Toolbar` |
| Overlay | `Dialog`, `AlertDialog`, `Drawer`, `Popover`, `MenuButton`, `Tooltip` |
| Disclosure | `Disclosure`, `Accordion` |
| Navigation | `Tabs`, `Breadcrumbs`, `Pagination` |
| Forms | `FormField`, `TextInput`, `TextareaField`, `SelectField`, `CheckboxField`, `ToggleField`, `RadioGroup`, `SliderField`, `SegmentedControl` |
| Status | `Badge`, `StatusPill`, `ProgressRail`, semantic rails |
| Feedback | `ToastProvider`, `Toaster`, `Banner`, `SkeletonRows`, `SkeletonBlock`, `EmptyState` |
| Layout | `Panel`, `SplitPane`, `AppShell`, `Separator`, `PropertyGrid`, `KeyValueList` |
| Collection | `ActionRecordTable`, `CommandPalette`, `DataToolbar`, `FilterBar`, `Stepper`, `Timeline` |

## Contract Requirements

- Every icon-only action requires an accessible name.
- Every overlay has an explicit close path and a labelled content region.
- Every form primitive supports controlled and uncontrolled use where practical.
- Every table or collection must avoid horizontal overflow at the viewport matrix in `scripts/verify-workbench.ts`.
- Color is never the only state channel; text and accessible labels carry the meaning.
- HELM product surfaces must compose core primitives instead of forking private UI.

## Maturity Labels

- `stable`: ready for app usage from public package exports.
- `product-composed`: route-grade or HELM-shaped component built from stable primitives.
- `contract-only`: documented boundary that needs implementation before broad reuse.

No current coverage item is allowed to stay `contract-only` without a release note and issue reference.
