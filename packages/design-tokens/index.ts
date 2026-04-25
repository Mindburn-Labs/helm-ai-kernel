/**
 * @helm/design-tokens — TypeScript Constants
 *
 * Exportable values for use in JS logic (responsive hooks,
 * positioned components, runtime style calculations).
 *
 * All pixel values match the CSS custom properties in tokens.css.
 */

/* ── Breakpoints ── */
export const BREAKPOINTS = {
  mobile: 390,
  tablet: 768,
  laptop: 1024,
  compact: 1080,
  desktop: 1280,
  wide: 1440,
} as const;

export type Breakpoint = keyof typeof BREAKPOINTS;

/* ── Layout Dimensions ── */
export const LAYOUT = {
  topbarHeight: 48,
  statusbarHeight: 32,
  toolrailWidth: 44,
  indexstripWidth: 240,
  promptbarHeight: 80,
  panelWidth: 420,
  sidebarWidth: 280,
  cockpitWidth: 360,
} as const;

/* ── Z-Index Scale ── */
export const Z_INDEX = {
  base: 0,
  canvas: 0,
  toolrail: 10,
  chips: 20,
  statusbar: 30,
  topbar: 40,
  panel: 50,
  dropdown: 55,
  overlay: 60,
  modal: 70,
  commandPalette: 80,
  toast: 90,
} as const;

/* ── Motion ── */
export const EASING = {
  out: 'cubic-bezier(0.16, 1, 0.3, 1)',
  inOut: 'cubic-bezier(0.4, 0, 0.2, 1)',
  spring: 'cubic-bezier(0.34, 1.56, 0.64, 1)',
} as const;

export const DURATION = {
  instant: 100,
  fast: 150,
  normal: 250,
  slow: 350,
  slower: 500,
} as const;

/* ── Spacing Scale (px) ── */
export const SPACE = {
  0: 0,
  1: 2,
  2: 4,
  3: 6,
  4: 8,
  5: 10,
  6: 12,
  8: 16,
  10: 20,
  12: 24,
  16: 32,
  20: 40,
  24: 48,
  32: 64,
  40: 80,
} as const;

/* ── Radii (px) ── */
export const RADII = {
  xs: 4,
  sm: 6,
  md: 8,
  lg: 12,
  xl: 16,
  '2xl': 22,
  '3xl': 28,
  full: 9999,
} as const;

/* ── Media Query Helpers ── */
export function mediaUp(bp: Breakpoint): string {
  return `(min-width: ${BREAKPOINTS[bp]}px)`;
}

export function mediaDown(bp: Breakpoint): string {
  return `(max-width: ${BREAKPOINTS[bp] - 1}px)`;
}

export function mediaBetween(bpMin: Breakpoint, bpMax: Breakpoint): string {
  return `(min-width: ${BREAKPOINTS[bpMin]}px) and (max-width: ${BREAKPOINTS[bpMax] - 1}px)`;
}
