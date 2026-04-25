# helm-studio — migration status (Phase 2a staging)

This directory is a staged copy of `helm/apps/helm-studio/` mirrored in preparation for Phase 2a of the HELM OSS/commercial boundary re-split.

## What's here

- Verbatim rsync of `helm/apps/helm-studio/` (excluding `node_modules/`, `dist/`, `.vite/`, `coverage/`, stale lint artifacts).
- `src/ext/` — extension-contract primitives (`ModuleManifest`, `registerModule`, `getMergedRoutes`, `<ExtensionSlot>`, 16 unit tests). These are already the canonical OSS shell contracts.
- `src/features/{approvals,channels,decision-inbox,evidence,knowledge,marketplace,skills}/` — the generic HELM operator surfaces destined for OSS. (Phase 1 extracted all Mindburn-specific features — titan, research, signals, people, programs, workforce — into `helm/modules/studio-*/`.)
- `src/api/`, `src/operator/`, `src/router/`, `src/stores/`, `src/queries/`, `src/types/`, `src/app/` — generic operator shell infrastructure.

## Adaptations (Phase 2a completion — done 2026-04-18)

All adaptations below landed. The OSS Studio now builds standalone in helm-oss.

1. **`src/main.tsx` — private-module loader.** ✅ Stripped the `await import('../../../modules/studio-*/src/index')` lines from the OSS copy; `loadPrivateModules()` is an intentional no-op. The helm (commercial) repo keeps its own `main.tsx` with the full dynamic-import chain.
2. **`vite.config.ts` — `server.fs.allow`.** ✅ Dropped `../../modules` entry (helm-specific). Kept `__dirname` + `../../packages` (for workspace-local `@helm/design-tokens`).
3. **`vite.config.ts` — `resolve.alias` for React.** ✅ Removed the app-local React alias — npm workspaces hoist React to `helm-oss/node_modules/react`, so `dedupe: ['react', 'react-dom']` alone is sufficient for single-copy resolution.
4. **`package.json` — workspace dependencies.** ✅ Changed `@helm/design-tokens: "workspace:*"` → `"*"` (npm-compatible; pnpm still workspace-links on the commercial side).
5. **`helm-oss/package.json` — workspace declaration.** ✅ Added `"workspaces": ["apps/*", "packages/*"]` to the helm-oss root manifest. `npm install` now resolves `@helm/design-tokens` via local symlink.
6. **`tsconfig.json` — broken `extends` reference.** ✅ Inlined the 12 compiler options from helm's `tsconfig.base.json` directly (helm-oss has no equivalent root base config; app-level self-contained config is cleaner).

## Verification (2026-04-18)

From `helm-oss/apps/helm-studio/`:

- `npx tsc --noEmit` → 0 errors
- `npx vitest run` → 30/30 passing (5 test files — same suite as helm's)
- `VITE_STUDIO_PROFILE=oss npx vite build --mode production` → 1.29s, chunks include generic surfaces (ActionInboxPage, ActionDetailPage, etc.) but zero `helm/modules/*` chunks (correct DCE)

## Commercial ↔ OSS divergence contract

Two files are intentionally different between helm's and helm-oss's copies of Studio:
- `src/main.tsx` — helm loads 6 private modules; helm-oss loads zero.
- `vite.config.ts` — helm's `server.fs.allow` includes `../../modules` + `../../packages`; helm-oss has only `../../packages`. helm's `resolve.alias` pins app-local React (pnpm nests); helm-oss relies on workspace hoisting + dedupe.

When `tools/sync-oss-kernel.sh` mirrors OSS → helm, these files must be **excluded from the protected manifest** (or commercial overlays them post-sync). The mirror-scope is enumerated in `helm/tools/boundary/protected.manifest`.

## Cross-repo sync expectations

Once adaptations are done + helm-oss commits this state:

1. Tag a helm-oss release (e.g. `v0.5.0-studio`).
2. Update `helm/tools/oss.lock` to pin that commit.
3. Extend `helm/protected.manifest` to cover `apps/helm-studio/**` and `packages/design-tokens/**`.
4. Run `helm/tools/sync-oss-kernel.sh` to mirror.
5. Verify `make verify-boundary` green in helm.
6. Retire `helm/apps/helm-studio/` (now served from mirror).

## Reference

- Full plan: `/.claude/plans/dynamic-orbiting-crayon.md`
- Memory: `~/.claude/projects/-Users-ivan-Code-Mindburn-Labs/memory/project_helm_oss_commercial_split.md`
