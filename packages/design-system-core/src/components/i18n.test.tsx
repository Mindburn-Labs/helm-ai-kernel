import { act, render, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  I18nProvider,
  useFormatDate,
  useFormatNumber,
  useFormatRelativeTime,
  useI18n,
} from "./i18n";

describe("I18nProvider", () => {
  beforeEach(() => {
    document.documentElement.removeAttribute("lang");
    document.documentElement.removeAttribute("dir");
  });

  afterEach(() => {
    document.documentElement.removeAttribute("lang");
    document.documentElement.removeAttribute("dir");
  });

  it("writes lang + dir attributes to <html> when applyToDocument is true", () => {
    render(
      <I18nProvider defaultLocale="en-US">
        <span />
      </I18nProvider>,
    );
    expect(document.documentElement.getAttribute("lang")).toBe("en-US");
    expect(document.documentElement.getAttribute("dir")).toBe("ltr");
  });

  it("detects RTL locales (ar, fa, he, ur) and sets dir=rtl", () => {
    render(
      <I18nProvider defaultLocale="ar-SA">
        <span />
      </I18nProvider>,
    );
    expect(document.documentElement.getAttribute("dir")).toBe("rtl");
  });

  it("does not write to <html> when applyToDocument is false", () => {
    render(
      <I18nProvider defaultLocale="ja-JP" applyToDocument={false}>
        <span />
      </I18nProvider>,
    );
    expect(document.documentElement.hasAttribute("lang")).toBe(false);
  });

  it("t() returns the message and interpolates {placeholder} params", () => {
    const messages = { greeting: "Hello, {name}! You have {count} alerts." };
    const { result } = renderHook(() => useI18n(), {
      wrapper: ({ children }) => (
        <I18nProvider defaultLocale="en-US" messages={messages}>
          {children}
        </I18nProvider>
      ),
    });
    expect(result.current?.t("greeting", { name: "Ivan", count: 3 })).toBe(
      "Hello, Ivan! You have 3 alerts.",
    );
  });

  it("t() returns the key when no message exists", () => {
    const { result } = renderHook(() => useI18n(), {
      wrapper: ({ children }) => <I18nProvider defaultLocale="en-US">{children}</I18nProvider>,
    });
    expect(result.current?.t("missing.key")).toBe("missing.key");
  });

  it("setLocale updates the locale and direction", () => {
    const { result } = renderHook(() => useI18n(), {
      wrapper: ({ children }) => <I18nProvider defaultLocale="en-US">{children}</I18nProvider>,
    });
    expect(result.current?.direction).toBe("ltr");
    act(() => result.current?.setLocale("he-IL"));
    expect(result.current?.locale).toBe("he-IL");
    expect(result.current?.direction).toBe("rtl");
  });

  it("useFormatNumber respects locale (en-US uses commas, de-DE uses dots)", () => {
    const wrapEn = ({ children }: { children: React.ReactNode }) => (
      <I18nProvider defaultLocale="en-US">{children}</I18nProvider>
    );
    const wrapDe = ({ children }: { children: React.ReactNode }) => (
      <I18nProvider defaultLocale="de-DE">{children}</I18nProvider>
    );
    const { result: en } = renderHook(() => useFormatNumber(), { wrapper: wrapEn });
    const { result: de } = renderHook(() => useFormatNumber(), { wrapper: wrapDe });
    expect(en.current(1234.5)).toMatch(/1,234/);
    expect(de.current(1234.5)).toMatch(/1\.234/);
  });

  it("useFormatRelativeTime returns a localized phrase", () => {
    const { result } = renderHook(() => useFormatRelativeTime(), {
      wrapper: ({ children }) => <I18nProvider defaultLocale="en-US">{children}</I18nProvider>,
    });
    expect(result.current(-1, "day")).toMatch(/yesterday/i);
    expect(result.current(2, "hour")).toMatch(/in 2 hours/i);
  });

  it("useI18n + useFormatDate degrade to ISO when used outside provider", () => {
    const { result: ctx } = renderHook(() => useI18n());
    const { result: fmt } = renderHook(() => useFormatDate());
    expect(ctx.current).toBeNull();
    expect(fmt.current(new Date("2026-04-29T00:00:00Z"))).toBe("2026-04-29");
  });
});
