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
 * Lightweight i18n primitive — locale + message-catalog + Intl helpers
 * exposed through a React context. Intentionally minimal: no FormatJS
 * runtime, no plural-form library, no ICU MessageFormat parsing — those
 * land via the FormatJS adapter when the system formally enters non-EN
 * markets (per ROADMAP.md "Later" lane).
 *
 * What it provides today:
 *   - Locale (BCP-47) + dir (ltr | rtl) inferred from locale
 *   - A `t(key, params?)` lookup that does {placeholder} interpolation
 *   - Pre-bound, cached Intl.* formatters (number / compact / currency
 *     / date / dateTime / relativeTime / list)
 *   - `useFormatNumber()`, `useFormatDate()`, `useFormatRelativeTime()`
 *     convenience hooks
 *
 * Pairs with `<ThemeProvider>` — `<I18nProvider>` additionally writes
 * `lang` and `dir` to `<html>` so CSS logical properties + browser
 * hyphenation resolve correctly under RTL.
 */

export type Locale = string;
export type Direction = "ltr" | "rtl";
export type MessageCatalog = Readonly<Record<string, string>>;

const RTL_PREFIXES = ["ar", "fa", "he", "ur", "ps", "sd", "yi"] as const;

function detectDirection(locale: Locale): Direction {
  const lang = locale.split("-")[0]?.toLowerCase() ?? "";
  return RTL_PREFIXES.some((p) => lang === p) ? "rtl" : "ltr";
}

interface IntlBag {
  readonly numberFormat: Intl.NumberFormat;
  readonly compactNumberFormat: Intl.NumberFormat;
  readonly currencyFormat: (currency: string) => Intl.NumberFormat;
  readonly dateFormat: Intl.DateTimeFormat;
  readonly dateTimeFormat: Intl.DateTimeFormat;
  readonly relativeTimeFormat: Intl.RelativeTimeFormat;
  readonly listFormat: Intl.ListFormat;
}

function buildIntlBag(locale: Locale): IntlBag {
  const currencyCache = new Map<string, Intl.NumberFormat>();
  return {
    numberFormat: new Intl.NumberFormat(locale),
    compactNumberFormat: new Intl.NumberFormat(locale, { notation: "compact" }),
    currencyFormat: (currency: string) => {
      const cached = currencyCache.get(currency);
      if (cached) return cached;
      const next = new Intl.NumberFormat(locale, { style: "currency", currency });
      currencyCache.set(currency, next);
      return next;
    },
    dateFormat: new Intl.DateTimeFormat(locale, { dateStyle: "medium" }),
    dateTimeFormat: new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }),
    relativeTimeFormat: new Intl.RelativeTimeFormat(locale, { numeric: "auto" }),
    listFormat: new Intl.ListFormat(locale, { style: "long", type: "conjunction" }),
  };
}

export interface I18nContextValue {
  readonly locale: Locale;
  readonly direction: Direction;
  readonly setLocale: (next: Locale) => void;
  readonly t: (key: string, params?: Readonly<Record<string, string | number>>) => string;
  readonly intl: IntlBag;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function useI18n(): I18nContextValue | null {
  return useContext(I18nContext);
}

export function useFormatNumber(): (value: number) => string {
  const ctx = useI18n();
  return useCallback((value: number) => (ctx ? ctx.intl.numberFormat.format(value) : String(value)), [ctx]);
}

export function useFormatDate(): (value: Date | number) => string {
  const ctx = useI18n();
  return useCallback(
    (value: Date | number) =>
      ctx ? ctx.intl.dateFormat.format(value) : new Date(value).toISOString().slice(0, 10),
    [ctx],
  );
}

export function useFormatRelativeTime(): (value: number, unit: Intl.RelativeTimeFormatUnit) => string {
  const ctx = useI18n();
  return useCallback(
    (value: number, unit: Intl.RelativeTimeFormatUnit) =>
      ctx ? ctx.intl.relativeTimeFormat.format(value, unit) : `${value} ${unit}`,
    [ctx],
  );
}

function interpolate(template: string, params: Readonly<Record<string, string | number>> = {}): string {
  return template.replace(/\{(\w+)\}/g, (match, key: string) => {
    const value = params[key];
    return value === undefined ? match : String(value);
  });
}

export interface I18nProviderProps {
  readonly children: ReactNode;
  readonly defaultLocale?: Locale;
  /** Optional message catalog. Keys are dot-namespaced strings. */
  readonly messages?: MessageCatalog;
  /**
   * If true, write `lang` + `dir` attributes to `document.documentElement`
   * whenever the locale changes. Default true.
   */
  readonly applyToDocument?: boolean;
}

export function I18nProvider({
  children,
  defaultLocale,
  messages = {},
  applyToDocument = true,
}: I18nProviderProps) {
  const initialLocale =
    defaultLocale ?? (typeof navigator !== "undefined" ? navigator.language : "en-US");
  const [locale, setLocaleState] = useState<Locale>(initialLocale);

  const direction = detectDirection(locale);
  const intl = useMemo<IntlBag>(() => buildIntlBag(locale), [locale]);

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
  }, []);

  useEffect(() => {
    if (!applyToDocument || typeof document === "undefined") return;
    document.documentElement.setAttribute("lang", locale);
    document.documentElement.setAttribute("dir", direction);
  }, [locale, direction, applyToDocument]);

  const t = useCallback(
    (key: string, params?: Readonly<Record<string, string | number>>) => {
      const template = messages[key];
      if (template === undefined) return key;
      return interpolate(template, params);
    },
    [messages],
  );

  const value = useMemo<I18nContextValue>(
    () => ({ locale, direction, setLocale, t, intl }),
    [locale, direction, setLocale, t, intl],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}
