# Architecture

HELM OSS ships one product frontend and one design-system package:

- `apps/console` is the single self-hostable HELM OSS Console.
- `packages/design-system-core` is the public `@mindburn/ui-core` React/token package.

`@mindburn/ui-core` owns generic tokens, state semantics, React primitives, layout, tables, forms, feedback, inspection views, providers, and static CSS. The Console consumes that package through public entrypoints and may add app-local composition, but it must not fork styling or create a second component system.

Commercial HELM applications may mirror or consume this package, but `helm-oss` does not contain HELM product-pattern packages, workbench apps, or starter apps.

Consumers must import from published package entrypoints only. Deep imports from `src`, `dist` internals, or relative workspace paths are unsupported and covered by the package smoke test and Console build.
