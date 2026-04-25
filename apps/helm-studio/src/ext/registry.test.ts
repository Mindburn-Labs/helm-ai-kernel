import { beforeEach, describe, expect, it } from 'vitest';
import type { RouteObject } from 'react-router-dom';
import {
  __resetRegistryForTests,
  getContributedMenu,
  getContributedRoutes,
  getMergedRoutes,
  getRegisteredModules,
  getSlotContributions,
  registerModule,
  setAvailableCapabilities,
} from './registry';
import type { ModuleManifest } from './types';

// Minimal placeholder component — the registry never renders it, so the type
// contract is all that matters here.
const Noop = (): null => null;

function manifest(overrides: Partial<ModuleManifest> & Pick<ModuleManifest, 'id'>): ModuleManifest {
  return {
    title: overrides.id,
    ...overrides,
  };
}

describe('ext/registry', () => {
  beforeEach(() => {
    __resetRegistryForTests();
  });

  describe('registerModule', () => {
    it('accepts a module with just id and title', () => {
      registerModule(manifest({ id: 'mod.a' }));
      expect(getRegisteredModules().map((m) => m.id)).toEqual(['mod.a']);
    });

    it('throws on duplicate id', () => {
      registerModule(manifest({ id: 'mod.a' }));
      expect(() => registerModule(manifest({ id: 'mod.a' }))).toThrow(
        /already registered: mod\.a/,
      );
    });

    it('throws when a required capability is missing', () => {
      setAvailableCapabilities(['cap.x']);
      expect(() =>
        registerModule(manifest({ id: 'mod.a', requiredCapabilities: ['cap.x', 'cap.y'] })),
      ).toThrow(/missing capabilities: cap\.y/);
    });

    it('accepts a module once all required capabilities are available', () => {
      setAvailableCapabilities(['cap.x', 'cap.y']);
      registerModule(manifest({ id: 'mod.a', requiredCapabilities: ['cap.x', 'cap.y'] }));
      expect(getRegisteredModules().map((m) => m.id)).toEqual(['mod.a']);
    });
  });

  describe('setAvailableCapabilities', () => {
    it('replaces the set on subsequent calls', () => {
      setAvailableCapabilities(['cap.x']);
      setAvailableCapabilities(['cap.y']);
      expect(() =>
        registerModule(manifest({ id: 'mod.a', requiredCapabilities: ['cap.x'] })),
      ).toThrow(/missing capabilities: cap\.x/);
    });
  });

  describe('getRegisteredModules', () => {
    it('returns modules sorted by id', () => {
      registerModule(manifest({ id: 'mod.c' }));
      registerModule(manifest({ id: 'mod.a' }));
      registerModule(manifest({ id: 'mod.b' }));
      expect(getRegisteredModules().map((m) => m.id)).toEqual(['mod.a', 'mod.b', 'mod.c']);
    });
  });

  describe('getContributedRoutes', () => {
    it('flattens routes across modules', () => {
      registerModule(
        manifest({ id: 'mod.a', routes: [{ id: 'route.a', path: '/a', element: null }] }),
      );
      registerModule(
        manifest({ id: 'mod.b', routes: [{ id: 'route.b', path: '/b', element: null }] }),
      );
      expect(getContributedRoutes().map((r) => r.id)).toEqual(['route.a', 'route.b']);
    });
  });

  describe('getSlotContributions', () => {
    it('filters by slotId', () => {
      registerModule(
        manifest({
          id: 'mod.a',
          widgets: [
            { slotId: 'operator.sidebar', id: 'w.s', component: Noop },
            { slotId: 'canvas.toolbar', id: 'w.c', component: Noop },
          ],
        }),
      );
      expect(getSlotContributions('operator.sidebar').map((w) => w.id)).toEqual(['w.s']);
      expect(getSlotContributions('canvas.toolbar').map((w) => w.id)).toEqual(['w.c']);
    });

    it('sorts by order, ties broken by `${moduleId}:${id}`', () => {
      registerModule(
        manifest({
          id: 'mod.b',
          widgets: [
            { slotId: 'operator.sidebar', id: 'w1', order: 10, component: Noop },
            { slotId: 'operator.sidebar', id: 'w2', order: 5, component: Noop },
          ],
        }),
      );
      registerModule(
        manifest({
          id: 'mod.a',
          widgets: [
            // same order as mod.b:w2 — tie should break to 'mod.a:w0' first
            { slotId: 'operator.sidebar', id: 'w0', order: 5, component: Noop },
          ],
        }),
      );
      const ids = getSlotContributions('operator.sidebar').map(
        (w) => `${w.moduleId}:${w.id}`,
      );
      expect(ids).toEqual(['mod.a:w0', 'mod.b:w2', 'mod.b:w1']);
    });

    it('treats missing order as 0', () => {
      registerModule(
        manifest({
          id: 'mod.a',
          widgets: [
            { slotId: 'operator.sidebar', id: 'w1', component: Noop }, // order: undefined
            { slotId: 'operator.sidebar', id: 'w2', order: -1, component: Noop },
          ],
        }),
      );
      const ids = getSlotContributions('operator.sidebar').map((w) => w.id);
      expect(ids).toEqual(['w2', 'w1']);
    });
  });

  describe('getContributedMenu', () => {
    it('filters by section when given', () => {
      registerModule(
        manifest({
          id: 'mod.a',
          menu: [
            { id: 'm.primary', label: 'P', to: '/p', section: 'primary' },
            { id: 'm.admin', label: 'A', to: '/a', section: 'admin' },
          ],
        }),
      );
      expect(getContributedMenu('primary').map((m) => m.id)).toEqual(['m.primary']);
      expect(getContributedMenu('admin').map((m) => m.id)).toEqual(['m.admin']);
    });

    it('returns all entries when section is omitted', () => {
      registerModule(
        manifest({
          id: 'mod.a',
          menu: [{ id: 'm.p', label: 'P', to: '/p', section: 'primary' }],
        }),
      );
      registerModule(
        manifest({
          id: 'mod.b',
          menu: [{ id: 'm.a', label: 'A', to: '/a', section: 'admin' }],
        }),
      );
      expect(getContributedMenu().map((m) => `${m.moduleId}:${m.id}`)).toEqual([
        'mod.a:m.p',
        'mod.b:m.a',
      ]);
    });
  });

  describe('getMergedRoutes', () => {
    it('returns base routes unchanged when no modules contribute', () => {
      const base: RouteObject[] = [{ path: '/home', element: null }];
      expect(getMergedRoutes(base)).toEqual(base);
    });

    it('appends top-level contributions (no parentPath) as siblings', () => {
      const base: RouteObject[] = [{ path: '/home', element: null }];
      registerModule(
        manifest({
          id: 'mod.a',
          routes: [{ id: 'route.a', path: '/a', element: null }],
        }),
      );
      const merged = getMergedRoutes(base);
      expect(merged.map((r) => r.path)).toEqual(['/home', '/a']);
    });

    it('inserts nested contributions under the matching parentPath', () => {
      const base: RouteObject[] = [
        {
          path: '/workspaces/:workspaceId',
          element: null,
          children: [{ path: 'canvas', element: null }],
        },
      ];
      registerModule(
        manifest({
          id: 'mod.a',
          routes: [
            {
              id: 'route.research',
              path: 'research',
              element: null,
              parentPath: '/workspaces/:workspaceId',
            },
          ],
        }),
      );
      const merged = getMergedRoutes(base);
      const workspaceRoute = merged[0]!;
      const childPaths = (workspaceRoute.children ?? []).map((c) => c.path);
      expect(childPaths).toEqual(['canvas', 'research']);
    });

    it('strips parentPath metadata from the merged route so react-router ignores it', () => {
      const base: RouteObject[] = [
        { path: '/workspaces/:workspaceId', element: null, children: [] },
      ];
      registerModule(
        manifest({
          id: 'mod.a',
          routes: [
            {
              id: 'route.research',
              path: 'research',
              element: null,
              parentPath: '/workspaces/:workspaceId',
            },
          ],
        }),
      );
      const merged = getMergedRoutes(base);
      const inserted = merged[0]!.children?.[0] as RouteObject & {
        parentPath?: string;
      };
      expect(inserted.parentPath).toBeUndefined();
      expect(inserted.path).toBe('research');
    });
  });
});
