# Architecture

HELM OSS ships one frontend package: `packages/design-system-core`.

`@helm/design-system-core` owns generic tokens, state semantics, React primitives, layout, tables, forms, feedback, inspection views, providers, and static CSS. It is an OSS-safe UI contract for downstream product clients, not a browser product surface inside this repository.

Commercial HELM applications may mirror or consume this package, but `helm-oss` does not contain `@helm/design-system-helm`, `@helm/design-system-next`, a workbench app, or a Next starter.

Consumers must import from published package entrypoints only. Deep imports from `src`, `dist` internals, or relative workspace paths are unsupported and covered by the package smoke test.
