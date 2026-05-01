import { designTokenSource } from "./source";

/**
 * HELM token contract. `source.ts` is the canonical token source for generated
 * TypeScript and JSON artifacts; CSS parity tests keep runtime variables aligned.
 */

export const breakpoints = designTokenSource.breakpoints;

export type BreakpointKey = keyof typeof breakpoints;

export const spacing = designTokenSource.spacing;

export type SpacingKey = keyof typeof spacing;

export const radius = designTokenSource.radius;

export type RadiusKey = keyof typeof radius;

export const duration = designTokenSource.duration;

export type DurationKey = keyof typeof duration;

export const zIndex = designTokenSource.zIndex;

export type ZIndexKey = keyof typeof zIndex;

export const focusRing = designTokenSource.focusRing;

export const minTouchTarget = designTokenSource.minTouchTarget;
export const sidebarWidth = designTokenSource.sidebarWidth;
export const topbarHeight = designTokenSource.topbarHeight;

export const typographyFloors = designTokenSource.typographyFloors;

export const density = designTokenSource.density;

export type DensityKey = keyof typeof density;

export const approvedDynamicInlineStyles = designTokenSource.approvedDynamicInlineStyles;

/**
 * Build CSS `var(--helm-*)` references with type-safe keys.
 */
export const cssVar = {
  spacing: (key: SpacingKey) => `var(--helm-space-${key.slice(1)})`,
  radius: (key: RadiusKey) => `var(--helm-radius-${key})`,
  duration: (key: DurationKey) => (key === "legacy" ? "var(--helm-dur)" : `var(--helm-dur-${key})`),
  zIndex: (key: ZIndexKey) => `var(--helm-z-${key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)})`,
  focusRing: (which: "width" | "offset") => (which === "width" ? "var(--helm-focus-ring-w)" : "var(--helm-focus-ring-offset)"),
} as const;
