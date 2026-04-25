/**
 * API base URL resolution for the Studio.
 *
 * Resolution order (first non-empty wins):
 *   1. `globalThis.HELM_API_BASE_URL` — runtime override. A commercial build
 *      or a local-backend wrapper can set this via a `<script>` injection in
 *      `index.html` before the app bundle loads. This lets a single Studio
 *      build target either the hosted controlplane or a local `helm server
 *      --local` backend without a rebuild.
 *   2. `import.meta.env.VITE_API_BASE_URL` — Vite build-time env var. Pinning
 *      the base URL at build time is appropriate for fully-isolated
 *      single-tenant deployments.
 *   3. Empty string — paths resolve against `window.location.origin`. This
 *      is the current Studio default (Vite dev-server proxies `/api/v1/*`
 *      to the backend; production deploys co-locate Studio with its API on
 *      the same origin).
 *
 * Only absolute paths (starting with `/`) are rewritten. Full URLs pass
 * through unchanged so external resources (docs links, OAuth redirects,
 * third-party embeds) are never mis-prefixed.
 */

declare global {
  // Optional runtime override set by host page before the app bundle runs.
  // eslint-disable-next-line no-var
  var HELM_API_BASE_URL: string | undefined;
}

function resolveBaseUrl(): string {
  const runtime = (globalThis as { HELM_API_BASE_URL?: string }).HELM_API_BASE_URL;
  if (runtime && runtime.length > 0) {
    return stripTrailingSlash(runtime);
  }
  const buildTime = import.meta.env.VITE_API_BASE_URL as string | undefined;
  if (buildTime && buildTime.length > 0) {
    return stripTrailingSlash(buildTime);
  }
  return '';
}

function stripTrailingSlash(value: string): string {
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

/**
 * Prefix the configured base URL onto absolute paths. Non-absolute inputs
 * (full URLs, blob: URIs, etc.) pass through unchanged.
 */
export function apiPath(path: string): string {
  if (!path.startsWith('/')) {
    return path;
  }
  const base = resolveBaseUrl();
  return base + path;
}
