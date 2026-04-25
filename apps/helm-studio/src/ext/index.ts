/**
 * Public surface of the Studio extension system.
 *
 * Private modules under `helm/modules/studio-*` import from here to register
 * themselves. Shell components import from here to mount `<ExtensionSlot />`
 * and, at boot, to merge contributed routes and menu entries.
 */

export type {
  ExtensionSlotId,
  MenuContribution,
  ModuleManifest,
  RouteContribution,
  SlotContribution,
  StudioProfile,
} from './types';

export {
  getContributedMenu,
  getContributedRoutes,
  getMergedRoutes,
  getRegisteredModules,
  getSlotContributions,
  registerModule,
  setAvailableCapabilities,
} from './registry';

export { ExtensionSlot } from './slot';
