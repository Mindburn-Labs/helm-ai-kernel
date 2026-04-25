import type { RouteObject } from 'react-router-dom';
import type {
  ExtensionSlotId,
  MenuContribution,
  ModuleManifest,
  RouteContribution,
  SlotContribution,
} from './types';

/**
 * Module registry.
 *
 * The Studio shell imports this module once at boot, calls
 * `setAvailableCapabilities()` with the kernel capabilities the runtime
 * exposes, then modules register themselves by import-time side effect
 * (each private module file calls `registerModule({...})`).
 *
 * The registry is deliberately small and deterministic. No async, no
 * reactive store, no React.
 */

const modules = new Map<string, ModuleManifest>();
const availableCapabilities = new Set<string>();

/**
 * Declare what OSS kernel capabilities the runtime provides for this build.
 * Called once at app boot by the shell. Calling again replaces the set.
 */
export function setAvailableCapabilities(caps: readonly string[]): void {
  availableCapabilities.clear();
  for (const cap of caps) {
    availableCapabilities.add(cap);
  }
}

/**
 * Register a module. Throws synchronously if:
 *   - a module with the same id is already registered
 *   - any required capability is not currently available
 *
 * Typical usage: private module files call this at import time.
 */
export function registerModule(manifest: ModuleManifest): void {
  if (modules.has(manifest.id)) {
    throw new Error(`[ext] module already registered: ${manifest.id}`);
  }
  const missing = (manifest.requiredCapabilities ?? []).filter(
    (cap) => !availableCapabilities.has(cap),
  );
  if (missing.length > 0) {
    throw new Error(
      `[ext] module ${manifest.id} requires missing capabilities: ${missing.join(', ')}`,
    );
  }
  modules.set(manifest.id, manifest);
}

/** Return all registered modules, sorted by id for determinism. */
export function getRegisteredModules(): readonly ModuleManifest[] {
  return [...modules.values()].sort((a, b) => a.id.localeCompare(b.id));
}

/** Collect every route contributed by every registered module. */
export function getContributedRoutes(): readonly RouteContribution[] {
  return getRegisteredModules().flatMap((m) => m.routes ?? []);
}

/** Strip ext-only metadata (`parentPath`) from a contribution before handing to react-router. */
function toRouteObject(contribution: RouteContribution): RouteObject {
  const { parentPath: _parentPath, ...routeObject } = contribution;
  return routeObject as RouteObject;
}

/**
 * Recursively insert nested contributions under matching parent routes.
 * A contribution with `parentPath === route.path` is appended to that
 * route's `children` array. Non-matching contributions are threaded into
 * nested subtrees.
 */
function insertNestedContributions(
  routes: readonly RouteObject[],
  nested: readonly RouteContribution[],
): RouteObject[] {
  return routes.map((route) => {
    const matching = nested.filter((c) => c.parentPath === route.path);
    const existingChildren = route.children
      ? insertNestedContributions(route.children, nested)
      : undefined;
    const nextChildren = matching.length
      ? [...(existingChildren ?? []), ...matching.map(toRouteObject)]
      : existingChildren;
    if (nextChildren === route.children) {
      return route;
    }
    return { ...route, children: nextChildren } as RouteObject;
  });
}

/**
 * Merge module route contributions into the shell's base route tree.
 *
 * Contributions with a `parentPath` are inserted as children under the
 * matching parent route (at any depth). Contributions without a parent
 * become top-level siblings. Insertion order is deterministic — it
 * follows the order of `getContributedRoutes()` (which itself is sorted
 * by module id).
 *
 * Shell code should call this once when constructing `appRoutes`.
 */
export function getMergedRoutes(
  baseRoutes: readonly RouteObject[],
): readonly RouteObject[] {
  const contributions = getContributedRoutes();
  const nested = contributions.filter((c) => c.parentPath !== undefined);
  const topLevel = contributions.filter((c) => c.parentPath === undefined);
  const withNested = insertNestedContributions(baseRoutes, nested);
  return [...withNested, ...topLevel.map(toRouteObject)];
}

/**
 * Collect widgets contributed to a given slot, sorted by `order` (ascending,
 * default 0) with ties broken lexicographically on `${moduleId}:${id}`.
 */
export function getSlotContributions(
  slotId: ExtensionSlotId,
): readonly (SlotContribution & { moduleId: string })[] {
  const items = getRegisteredModules().flatMap((module) =>
    (module.widgets ?? [])
      .filter((widget) => widget.slotId === slotId)
      .map((widget) => ({ ...widget, moduleId: module.id })),
  );
  return items.sort((a, b) => {
    const orderDelta = (a.order ?? 0) - (b.order ?? 0);
    if (orderDelta !== 0) return orderDelta;
    return `${a.moduleId}:${a.id}`.localeCompare(`${b.moduleId}:${b.id}`);
  });
}

/**
 * Collect menu entries contributed by every registered module, optionally
 * filtered to a section. Sorted by `order` then `${moduleId}:${id}`.
 */
export function getContributedMenu(
  section?: MenuContribution['section'],
): readonly (MenuContribution & { moduleId: string })[] {
  const items = getRegisteredModules().flatMap((module) =>
    (module.menu ?? [])
      .filter((entry) => section === undefined || entry.section === section)
      .map((entry) => ({ ...entry, moduleId: module.id })),
  );
  return items.sort((a, b) => {
    const orderDelta = (a.order ?? 0) - (b.order ?? 0);
    if (orderDelta !== 0) return orderDelta;
    return `${a.moduleId}:${a.id}`.localeCompare(`${b.moduleId}:${b.id}`);
  });
}

/**
 * Test helper. Clears all registered modules and capability state.
 * Do not call from production code.
 */
export function __resetRegistryForTests(): void {
  modules.clear();
  availableCapabilities.clear();
}
