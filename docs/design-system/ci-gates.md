# CI Gates

`npm run verify` is the release gate for handoff and package publishing.

It runs:

1. `tokens:check`
2. workspace `typecheck`
3. `lint`
4. unit tests
5. package builds
6. workbench build
7. Next starter build
8. quality checks
9. package smoke checks
10. e2e checks
11. accessibility checks
12. reduced-motion checks
13. forced-colors checks
14. visual checks

## Package Smoke Coverage

The smoke gate verifies:

- `npm pack --dry-run` succeeds for every publishable package.
- package metadata includes `license`, `main`, `module`, `types`, and public publish config.
- package tarballs include `README.md`, `dist/index.js`, and `dist/index.d.ts`.
- core exports CSS, token JSON, state, tokens, component subpaths, and primitive coverage metadata.
- HELM exports CSS, assistant, components, handoff, patterns, routes, and state subpaths.
- Next exports App Router helpers.
- runtime ESM imports work from built package entrypoints.
- a temporary consumer project typechecks public imports and CSS imports.

## Quality Coverage

The quality gate rejects:

- hard-coded colors outside token source files.
- private package or source imports.
- Next starter usage that bypasses public package APIs.
- generated package output committed under `src`.

Add new checks when a production rule becomes important enough that a reviewer should not have to remember it manually.
