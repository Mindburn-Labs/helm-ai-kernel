"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

/**
 * `ThemeProvider` — runtime theme + density orchestration. Sets
 * `data-theme` and `data-density` attributes on a target element
 * (default `document.documentElement`), exposes a `useTheme()` hook for
 * consumers to read/write the active values, and persists them to
 * localStorage by default.
 *
 * Pairs with the existing CSS in tokens.css which already keys all
 * semantic tokens off the `[data-theme="light"]` / `[data-density=…]`
 * attributes. No CSS changes required — this is the React API surface
 * over the attribute contract.
 */

export type ThemeMode = "light" | "dark";
export type ThemePreference = "auto" | ThemeMode;
export type ThemeDensity = "compact" | "comfortable";

export interface ThemeContextValue {
  /** The user's chosen preference (light, dark, or auto). */
  readonly preference: ThemePreference;
  /** The resolved active mode (auto → matches system). */
  readonly resolvedMode: ThemeMode;
  readonly density: ThemeDensity;
  readonly setPreference: (next: ThemePreference) => void;
  readonly setDensity: (next: ThemeDensity) => void;
  readonly toggleMode: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

/**
 * Read the active theme + density. Returns `null` when used outside a
 * `ThemeProvider` so consumers can degrade gracefully.
 */
export function useTheme(): ThemeContextValue | null {
  return useContext(ThemeContext);
}

const DEFAULT_STORAGE_KEY = "helm.theme";
const DEFAULT_DENSITY_KEY = "helm.density";

function readStored(key: string, fallback: string): string {
  if (typeof window === "undefined") return fallback;
  try {
    const value = window.localStorage.getItem(key);
    return value ?? fallback;
  } catch {
    return fallback;
  }
}

function writeStored(key: string, value: string) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // localStorage may be blocked (private mode, quota) — no-op.
  }
}

function detectSystemMode(): ThemeMode {
  if (typeof window === "undefined" || !window.matchMedia) return "dark";
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export interface ThemeProviderProps {
  readonly children: ReactNode;
  readonly defaultPreference?: ThemePreference;
  readonly defaultDensity?: ThemeDensity;
  /** When true, persists changes to localStorage. Default true. */
  readonly persist?: boolean;
  readonly storageKey?: string;
  readonly densityStorageKey?: string;
  /**
   * Element to receive the `data-theme` / `data-density` attributes.
   * Defaults to `document.documentElement`. Pass an element to scope
   * the theme to a sub-tree (e.g. for theme switchers in stories).
   */
  readonly target?: HTMLElement | null;
}

export function ThemeProvider({
  children,
  defaultPreference = "auto",
  defaultDensity = "compact",
  persist = true,
  storageKey = DEFAULT_STORAGE_KEY,
  densityStorageKey = DEFAULT_DENSITY_KEY,
  target,
}: ThemeProviderProps) {
  const [preference, setPreferenceState] = useState<ThemePreference>(() => {
    if (!persist) return defaultPreference;
    const stored = readStored(storageKey, defaultPreference);
    if (stored === "light" || stored === "dark" || stored === "auto") return stored;
    return defaultPreference;
  });

  const [density, setDensityState] = useState<ThemeDensity>(() => {
    if (!persist) return defaultDensity;
    const stored = readStored(densityStorageKey, defaultDensity);
    return stored === "comfortable" ? "comfortable" : "compact";
  });

  const [systemMode, setSystemMode] = useState<ThemeMode>(detectSystemMode);

  // Mirror system preference for `auto` mode.
  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return undefined;
    const mql = window.matchMedia("(prefers-color-scheme: light)");
    const handler = (event: MediaQueryListEvent) => {
      setSystemMode(event.matches ? "light" : "dark");
    };
    if (typeof mql.addEventListener === "function") {
      mql.addEventListener("change", handler);
      return () => mql.removeEventListener("change", handler);
    }
    mql.addListener(handler);
    return () => mql.removeListener(handler);
  }, []);

  const resolvedMode: ThemeMode = preference === "auto" ? systemMode : preference;

  // Apply data-theme + data-density to the target element.
  useEffect(() => {
    if (typeof document === "undefined") return;
    const element = target ?? document.documentElement;
    if (preference === "auto") {
      element.removeAttribute("data-theme");
    } else {
      element.setAttribute("data-theme", preference);
    }
    element.setAttribute("data-density", density);
  }, [preference, density, target]);

  const setPreference = useCallback(
    (next: ThemePreference) => {
      setPreferenceState(next);
      if (persist) writeStored(storageKey, next);
    },
    [persist, storageKey],
  );

  const setDensity = useCallback(
    (next: ThemeDensity) => {
      setDensityState(next);
      if (persist) writeStored(densityStorageKey, next);
    },
    [persist, densityStorageKey],
  );

  const toggleMode = useCallback(() => {
    setPreference(resolvedMode === "light" ? "dark" : "light");
  }, [resolvedMode, setPreference]);

  const value = useMemo<ThemeContextValue>(
    () => ({ preference, resolvedMode, density, setPreference, setDensity, toggleMode }),
    [preference, resolvedMode, density, setPreference, setDensity, toggleMode],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}
