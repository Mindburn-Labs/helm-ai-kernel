# helm-studio — OSS migration status

Tracks the cross-repo move of `apps/helm-studio/` from the commercial `helm/`
repo into `helm-oss/` as part of Phase 2a of the approved OSS/commercial split
(plan: `/Users/ivan/.claude/plans/dynamic-orbiting-crayon.md`; rationale:
"Open-source the best local product. Sell the shared organizational control
plane.").

## Phase 2a — Studio mirror staged

The Studio app tree (~132 files) has been `rsync`'d from
`helm/apps/helm-studio/` into this directory. Excluded paths:
`node_modules/`, `dist/`, `.vite/`, `coverage/`, `lint_output.txt`,
`lint_results.json`, `clean.json`.

The mirror is functional: `npm install` hoists deps into the
`helm-oss/node_modules/` root; `tsc --noEmit`, `vitest run`, and
`vite build` all succeed in both `VITE_STUDIO_PROFILE=oss` and
`VITE_STUDIO_PROFILE=commercial` modes (the latter is a build-time no-op in
OSS because `loadPrivateModules()` has an empty body here — see below).

## OSS ↔ commercial divergence contract

Only **two** files intentionally diverge between the OSS mirror and the
commercial source of truth. Every other file is byte-identical and must stay
that way so the `helm/tools/oss.lock` + `make sync-oss-kernel` sync ritual
can treat this directory as a read-through mirror.

| File | OSS (this repo) | helm (commercial) |
|---|---|---|
| `src/main.tsx` | `loadPrivateModules()` body is intentionally empty | `loadPrivateModules()` dynamically imports the six `helm/modules/studio-{titan,research-lab,signals-premium,people-ops,programs,workforce}/src/index` entries |
| `vite.config.ts` | `server.fs.allow` is `[app-root, ../../packages]`; no `resolve.alias` for React | `server.fs.allow` also includes `../../modules`; `resolve.alias` force-resolves React to the local `node_modules` (pnpm nests deps so a single copy is not guaranteed) |

Both divergences are about the commercial repo's `modules/*` private overlay
that does not (and must not) exist here. The shared guard
`import.meta.env.VITE_STUDIO_PROFILE === 'commercial'` plus Rollup dead-code
elimination means OSS builds never reach the missing code.

## Adaptations applied during Phase 2a

1. **`src/main.tsx` — `loadPrivateModules()` no-op.** Replaced six
   `await import('../../../modules/studio-*/src/index')` calls with a
   documented empty body. The `VITE_STUDIO_PROFILE === 'commercial'` guard
   is preserved so the divergence surface is a single function body.
2. **`vite.config.ts` — `server.fs.allow` narrowed.** Dropped
   `../../modules` (no `modules/` tree in OSS). Kept `../../packages` so the
   Vite dev server can serve `@helm/design-tokens/*.css`.
3. **`vite.config.ts` — `resolve.alias` for React removed.** OSS relies on
   npm-workspace hoisting plus `dedupe: ['react', 'react-dom']` for
   single-copy resolution. The commercial build keeps the alias because
   pnpm's nested layout needs the hard pin.
4. **`tsconfig.json` — base config inlined.** The rsync'd file extended
   `../../tsconfig.base.json`, which does not exist in helm-oss. The 12
   compiler options from that base are now inlined alongside the two
   Studio-local overrides (`noUnusedLocals: false`,
   `noUnusedParameters: false`) and the `types` entry.
5. **`package.json` — workspace dep spec changed.** Swapped
   `"@helm/design-tokens": "workspace:*"` → `"@helm/design-tokens": "*"`.
   The latter is npm-workspace compatible; pnpm still links the workspace
   copy on the commercial side.
6. **`helm-oss/package.json` — `workspaces` field added.** Registered
   `"apps/*"` and `"packages/*"` so `npm install` hoists Studio's deps into
   the root `node_modules/` and symlinks
   `node_modules/@helm/design-tokens -> ../packages/design-tokens`.

## Verification

From `helm-oss/`:

```bash
npm install
# → installs ~460+ packages into helm-oss/node_modules (workspace hoisting)

cd apps/helm-studio
npx tsc --noEmit
# → 0 errors

npx vitest run
# → 30 tests passing across 5 test files

VITE_STUDIO_PROFILE=oss npx vite build --mode production
# → succeeds; no private-module chunks emitted

VITE_STUDIO_PROFILE=commercial npx vite build --mode production
# → also succeeds (in this repo the commercial profile is a build-time
#   no-op because loadPrivateModules() has an empty body; the divergence
#   only matters in the commercial repo where the modules/ overlay is
#   present)
```

## Next migration steps (not in this PR)

- **Phase 2c** — extend the OSS `helm` binary with `helm server --local`
  serving the routes Studio needs (genesis, packs, evidence, receipts,
  replay, approvals, connectors).
- **Phase 2d** — add baseUrl indirection in `src/api/*.ts` so the same
  build targets a local backend (OSS) or a hosted controlplane
  (commercial).
- **Phase 2e** — flow the cross-repo commit through `helm/tools/oss.lock`,
  extend `helm/protected.manifest`, run `helm/tools/sync-oss-kernel.sh`,
  and confirm `make verify-boundary` is green.
