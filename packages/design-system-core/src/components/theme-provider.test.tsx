import { act, render, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ThemeProvider, useTheme } from "./theme-provider";

const STORAGE_KEY = "helm.theme";
const DENSITY_STORAGE_KEY = "helm.density";

describe("ThemeProvider", () => {
  beforeEach(() => {
    document.documentElement.removeAttribute("data-theme");
    document.documentElement.removeAttribute("data-density");
    window.localStorage.clear();
    vi.stubGlobal(
      "matchMedia",
      vi.fn((query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addEventListener: () => {},
        removeEventListener: () => {},
        addListener: () => {},
        removeListener: () => {},
        dispatchEvent: () => true,
      })),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("writes data-theme + data-density to documentElement when preference is explicit", () => {
    render(
      <ThemeProvider defaultPreference="light" defaultDensity="comfortable">
        <span />
      </ThemeProvider>,
    );
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    expect(document.documentElement.getAttribute("data-density")).toBe("comfortable");
  });

  it("removes data-theme when preference is auto so the system query takes over", () => {
    render(
      <ThemeProvider defaultPreference="auto">
        <span />
      </ThemeProvider>,
    );
    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
    expect(document.documentElement.getAttribute("data-density")).toBe("compact");
  });

  it("toggleMode flips between light + dark and persists to localStorage", () => {
    function Probe() {
      const theme = useTheme();
      return (
        <button type="button" onClick={theme?.toggleMode}>
          {theme?.resolvedMode}
        </button>
      );
    }
    const { getByRole } = render(
      <ThemeProvider defaultPreference="light">
        <Probe />
      </ThemeProvider>,
    );
    const button = getByRole("button");
    expect(button).toHaveTextContent("light");
    act(() => button.click());
    expect(button).toHaveTextContent("dark");
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe("dark");
  });

  it("rehydrates preference + density from localStorage on mount", () => {
    window.localStorage.setItem(STORAGE_KEY, "light");
    window.localStorage.setItem(DENSITY_STORAGE_KEY, "comfortable");
    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => (
        <ThemeProvider defaultPreference="dark" defaultDensity="compact">
          {children}
        </ThemeProvider>
      ),
    });
    expect(result.current?.preference).toBe("light");
    expect(result.current?.density).toBe("comfortable");
  });

  it("useTheme returns null outside ThemeProvider", () => {
    const { result } = renderHook(() => useTheme());
    expect(result.current).toBeNull();
  });

  it("setDensity updates the attribute and persists when persist=true", () => {
    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => (
        <ThemeProvider defaultDensity="compact">{children}</ThemeProvider>
      ),
    });
    act(() => result.current?.setDensity("comfortable"));
    expect(document.documentElement.getAttribute("data-density")).toBe("comfortable");
    expect(window.localStorage.getItem(DENSITY_STORAGE_KEY)).toBe("comfortable");
  });

  it("does not persist when persist=false", () => {
    const { result } = renderHook(() => useTheme(), {
      wrapper: ({ children }) => (
        <ThemeProvider defaultPreference="dark" persist={false}>
          {children}
        </ThemeProvider>
      ),
    });
    act(() => result.current?.setPreference("light"));
    expect(window.localStorage.getItem(STORAGE_KEY)).toBeNull();
  });
});
