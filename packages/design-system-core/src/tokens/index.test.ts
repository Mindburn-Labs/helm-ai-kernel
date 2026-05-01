import { describe, expect, it } from "vitest";
// Vite's ?raw import returns the CSS source as a string at test time.
import tokensCss from "../styles/tokens.css?raw";
import {
  duration,
  focusRing,
  minTouchTarget,
  radius,
  sidebarWidth,
  spacing,
  topbarHeight,
  zIndex,
} from "./index";

function readVar(name: string): string | undefined {
  const re = new RegExp(`--${name}:\\s*([^;]+);`, "m");
  const match = tokensCss.match(re);
  return match?.[1]?.trim();
}

function readPx(name: string): number | undefined {
  const value = readVar(name);
  if (!value) return undefined;
  const match = value.match(/^(\d+(?:\.\d+)?)px$/);
  return match?.[1] ? Number(match[1]) : undefined;
}

function readMs(name: string): number | undefined {
  const value = readVar(name);
  if (!value) return undefined;
  const match = value.match(/^(\d+(?:\.\d+)?)ms$/);
  return match?.[1] ? Number(match[1]) : undefined;
}

function readInt(name: string): number | undefined {
  const value = readVar(name);
  if (!value) return undefined;
  const match = value.match(/^(\d+)$/);
  return match?.[1] ? Number(match[1]) : undefined;
}

describe("token parity (CSS ↔ TS)", () => {
  it("spacing", () => {
    expect(readPx("helm-space-1")).toBe(spacing.s1);
    expect(readPx("helm-space-2")).toBe(spacing.s2);
    expect(readPx("helm-space-3")).toBe(spacing.s3);
    expect(readPx("helm-space-4")).toBe(spacing.s4);
    expect(readPx("helm-space-5")).toBe(spacing.s5);
    expect(readPx("helm-space-6")).toBe(spacing.s6);
    expect(readPx("helm-space-8")).toBe(spacing.s8);
    expect(readPx("helm-space-10")).toBe(spacing.s10);
    expect(readPx("helm-space-12")).toBe(spacing.s12);
    expect(readPx("helm-space-16")).toBe(spacing.s16);
  });

  it("radius", () => {
    expect(readPx("helm-radius-xs")).toBe(radius.xs);
    expect(readPx("helm-radius-sm")).toBe(radius.sm);
    expect(readPx("helm-radius-md")).toBe(radius.md);
    expect(readPx("helm-radius-panel")).toBe(radius.panel);
    expect(readPx("helm-radius-pill")).toBe(radius.pill);
  });

  it("durations", () => {
    expect(readMs("helm-dur")).toBe(duration.legacy);
    expect(readMs("helm-dur-instant")).toBe(duration.instant);
    expect(readMs("helm-dur-fast")).toBe(duration.fast);
    expect(readMs("helm-dur-base")).toBe(duration.base);
    expect(readMs("helm-dur-slow")).toBe(duration.slow);
    expect(readMs("helm-dur-skeleton")).toBe(duration.skeleton);
  });

  it("z-index ladder", () => {
    expect(readInt("helm-z-base")).toBe(zIndex.base);
    expect(readInt("helm-z-sticky")).toBe(zIndex.sticky);
    expect(readInt("helm-z-topbar")).toBe(zIndex.topbar);
    expect(readInt("helm-z-sidebar")).toBe(zIndex.sidebar);
    expect(readInt("helm-z-drawer-backdrop")).toBe(zIndex.drawerBackdrop);
    expect(readInt("helm-z-drawer")).toBe(zIndex.drawer);
    expect(readInt("helm-z-modal")).toBe(zIndex.modal);
    expect(readInt("helm-z-toast")).toBe(zIndex.toast);
    expect(readInt("helm-z-palette-backdrop")).toBe(zIndex.paletteBackdrop);
    expect(readInt("helm-z-palette")).toBe(zIndex.palette);
  });

  it("focus ring + layout", () => {
    expect(readPx("helm-focus-ring-w")).toBe(focusRing.width);
    expect(readPx("helm-focus-ring-offset")).toBe(focusRing.offset);
    expect(readPx("helm-min-touch-target")).toBe(minTouchTarget);
    expect(readPx("helm-sidebar-w")).toBe(sidebarWidth);
    expect(readPx("helm-topbar-h")).toBe(topbarHeight);
  });

  it("z-index ladder is strictly monotonic (no collisions)", () => {
    const values = Object.values(zIndex);
    const sorted = [...values].sort((a, b) => a - b);
    expect(values).toEqual(sorted);
    expect(new Set(values).size).toBe(values.length);
  });
});
