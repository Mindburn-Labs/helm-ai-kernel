# CI Gates

`make test-design-system` is the OSS release gate for `@helm/design-system-core`.

It runs:

1. package install from `package-lock.json`
2. TypeScript typecheck
3. unit and contract tests
4. package build
5. package smoke checks
6. `npm pack --dry-run`

## Package Smoke Coverage

The smoke gate verifies:

- `npm pack --dry-run` succeeds for every publishable package.
- package metadata includes `license`, `main`, `module`, `types`, and public publish config.
- package tarballs include `README.md`, `dist/index.js`, and `dist/index.d.ts`.
- core exports CSS, token JSON, state, tokens, component subpaths, and primitive coverage metadata.
- runtime ESM imports work from built package entrypoints.
- a temporary consumer project typechecks public imports and CSS imports.

## Quality Coverage

The quality gate rejects:

- hard-coded colors outside token source files.
- private package or source imports.
- package exports that are not present in the packed tarball.
- component class names that lack shipped CSS selectors.
- dynamic inline styles that are not listed in `approvedDynamicInlineStyles`.
- generated package output committed under `src`.

Add new checks when a production rule becomes important enough that a reviewer should not have to remember it manually.
