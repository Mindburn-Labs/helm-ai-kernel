# HELM OSS Console Source Owner

## Audience

Use this file when changing the OSS console UI, its API client, schema adapter, smoke script, or styling.

## Responsibility

`apps/console` owns the browser surface for inspecting a local HELM OSS boundary. The public docs route is `helm-oss/console`; it should describe user-visible behavior, while this source owner doc keeps implementation paths discoverable for maintainers.

## Source Map

- `src/App.tsx` owns the main console shell.
- `src/api/client.ts` owns calls into the local HELM API boundary.
- `src/api/schema.ts` owns the browser-facing response types.
- `src/App.test.tsx` and `scripts/smoke-dist.mjs` own regression and smoke coverage.
- `src/styles.css` owns console-specific layout and visual states.

## Validation

Run the OSS docs and console checks before making public claims about this app:

```bash
make docs-coverage
make docs-truth
```

If the public docs describe a console feature, the feature must be visible in this directory or in a linked API route under `core/cmd/helm`.
