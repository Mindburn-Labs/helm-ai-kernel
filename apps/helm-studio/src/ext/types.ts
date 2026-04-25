import type { ComponentType } from 'react';
import type { RouteObject } from 'react-router-dom';

/**
 * Extension contract types for Studio private modules.
 *
 * Studio's generic shell (eventually in helm-oss) ships these contracts.
 * Mindburn-specific products (Titan, research-lab, signals-premium, people-ops)
 * plug in as private modules under `helm/modules/studio-*` via `registerModule()`.
 *
 * Design rules:
 *   - No feature flags. A surface exists iff its module registers.
 *   - Deterministic ordering: lower `order` renders first; ties break on id.
 *   - Manifests are data. Modules contribute routes, slot widgets, and menu items
 *     declaratively — no runtime mutation of the registry after boot.
 */

/** Identifier for a slot where modules may contribute widgets. */
export type ExtensionSlotId =
  | 'operator.sidebar'
  | 'operator.header'
  | 'evidence.pane'
  | 'canvas.toolbar'
  | 'decision-inbox.row-actions'
  | 'mission.detail.panel'
  | 'signal.card.badges'
  | 'principal.detail.panel'
  // Genesis ceremony slots — stubs for HELM Genesis M4–M9.
  // No module contributes here today; the identifiers reserve the surface so
  // future Genesis UX work can land without widening the union across a
  // boundary-sensitive file.
  | 'genesis.intake.source'
  | 'genesis.wargame.probe';

/** A React component contributed into a slot. */
export interface SlotContribution {
  /** Slot this widget mounts into. */
  slotId: ExtensionSlotId;
  /** Stable id — must be unique per (slotId, moduleId). Used for React keys. */
  id: string;
  /** Lower renders first. Ties break lexicographically on `${moduleId}:${id}`. */
  order?: number;
  /** The component rendered. Props are slot-defined; see ExtensionSlot. */
  component: ComponentType<Record<string, unknown>>;
}

/**
 * A top-level route contributed by a module, merged into the app router.
 *
 * Intersection (not interface extension) because `RouteObject` in
 * react-router-dom v7 is a discriminated union (index / non-index / layout
 * routes) and interfaces cannot extend unions.
 */
export type RouteContribution = RouteObject & {
  /** Required — used for diagnostics and duplicate detection. */
  id: string;
  /**
   * If set, this contribution is merged as a CHILD of the route whose
   * `path` matches `parentPath` in the shell's route tree. If unset,
   * the contribution becomes a top-level sibling to the shell's routes.
   *
   * Example: a module that contributes `/workspaces/:workspaceId/research`
   * as a child of `/workspaces/:workspaceId` sets
   * `parentPath: '/workspaces/:workspaceId'` and uses `path: 'research'`
   * (relative to parent, per react-router conventions).
   */
  parentPath?: string;
};

/** A navigation menu entry contributed by a module. */
export interface MenuContribution {
  /** Stable id — unique per module. */
  id: string;
  /** Display label. */
  label: string;
  /** Route path this entry navigates to. */
  to: string;
  /** Section key — shell decides grouping. */
  section?: 'primary' | 'secondary' | 'admin';
  /** Lower renders first. */
  order?: number;
}

/**
 * A module is a coherent unit of product functionality — e.g. the Titan
 * trading integration, the Research Lab, or a premium signals surface.
 * A module registers by declaring one of these manifests at import time.
 */
export interface ModuleManifest {
  /** Globally unique module id, e.g. `@mindburn-private/studio-titan`. */
  id: string;
  /** Human-readable title for diagnostics and admin surfaces. */
  title: string;
  /** Semver — informational only today. */
  version?: string;
  /** OSS kernel capabilities this module requires. Registry refuses load if any are missing. */
  requiredCapabilities?: readonly string[];
  /** Routes merged into the app router. */
  routes?: readonly RouteContribution[];
  /** Widgets mounted into slots. */
  widgets?: readonly SlotContribution[];
  /** Menu entries contributed to the shell. */
  menu?: readonly MenuContribution[];
}

/**
 * Build profile. Selected at build time — controls whether private modules
 * under `helm/modules/studio-*` are linked into the bundle.
 *
 * - `oss`:        generic HELM Studio only. No private modules.
 * - `commercial`: OSS shell + Mindburn-specific private modules.
 */
export type StudioProfile = 'oss' | 'commercial';
