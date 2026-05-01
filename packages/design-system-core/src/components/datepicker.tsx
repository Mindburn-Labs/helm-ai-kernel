"use client";

import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { ChevronLeft, ChevronRight, Calendar as CalendarIcon } from "lucide-react";
import { useFieldAttrs } from "./forms";

/**
 * Date primitives — `Calendar` (a focused, keyboard-first month grid) and
 * `DatePicker` (a labelled trigger that opens a Calendar in a popover and
 * commits the chosen ISO date to a hidden input for native form submission).
 *
 * Wires to FormField context (id, aria-describedby, aria-invalid,
 * aria-required) via `useFieldAttrs()` and to `<Form>` via the standard
 * `name` attribute on a hidden input — the visible label respects the
 * caller-supplied `format` while the FormData payload is always ISO
 * `YYYY-MM-DD` for predictable server parsing.
 */

/* ── Date helpers ──────────────────────────────────────────────────────── */

export type DateValue = Date | string | null;

function asDate(value: DateValue | undefined): Date | null {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) {
    return Number.isFinite(value.getTime()) ? new Date(value.getTime()) : null;
  }
  return parseISO(value);
}

function parseISO(input: string): Date | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})/.exec(trimmed);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]) - 1;
  const day = Number(match[3]);
  const date = new Date(year, month, day);
  return Number.isFinite(date.getTime()) ? date : null;
}

function formatISO(date: Date): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

function startOfMonth(date: Date): Date {
  return new Date(date.getFullYear(), date.getMonth(), 1);
}

function addDays(date: Date, days: number): Date {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate() + days);
}

function addMonths(date: Date, months: number): Date {
  const next = new Date(date.getFullYear(), date.getMonth() + months, 1);
  const lastOfNext = new Date(next.getFullYear(), next.getMonth() + 1, 0).getDate();
  next.setDate(Math.min(date.getDate(), lastOfNext));
  return next;
}

function isSameDay(a: Date, b: Date): boolean {
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

function clampDate(date: Date, min: Date | null, max: Date | null): Date {
  if (min && date < min) return new Date(min.getTime());
  if (max && date > max) return new Date(max.getTime());
  return date;
}

function localeWeekStart(locale: string): 0 | 1 {
  // Conservative subset: regions where Sunday opens the week. Default
  // Monday otherwise (matches ISO 8601 / most of Europe / ECMA defaults).
  const sundayFirst = ["en-US", "en-CA", "ja-JP", "ar", "he", "ko-KR", "zh-CN", "zh-TW"];
  return sundayFirst.some((prefix) => locale.startsWith(prefix)) ? 0 : 1;
}

/* ── Calendar ─────────────────────────────────────────────────────────── */

export interface CalendarProps {
  readonly value?: Date | null;
  readonly defaultValue?: Date | null;
  readonly onValueChange?: (value: Date) => void;
  readonly focusedDate?: Date;
  readonly onFocusedDateChange?: (date: Date) => void;
  readonly min?: Date;
  readonly max?: Date;
  readonly locale?: string;
  readonly weekStartsOn?: 0 | 1;
  readonly disabledDates?: (date: Date) => boolean;
  readonly label?: string;
  readonly autoFocus?: boolean;
}

const WEEKS = 6;

/**
 * Month-grid calendar with WAI-ARIA grid semantics. Keyboard:
 *
 *   ArrowLeft / Right       — ±1 day
 *   ArrowUp / Down          — ±7 days
 *   Home / End              — start / end of week
 *   PageUp / PageDown       — ±1 month
 *   Shift+PageUp / PageDown — ±1 year
 *   Enter / Space           — select focused date
 */
export function Calendar({
  value,
  defaultValue,
  onValueChange,
  focusedDate,
  onFocusedDateChange,
  min,
  max,
  locale,
  weekStartsOn,
  disabledDates,
  label,
  autoFocus = false,
}: CalendarProps) {
  const resolvedLocale = locale ?? (typeof navigator !== "undefined" ? navigator.language : "en-US");
  const startsOn = weekStartsOn ?? localeWeekStart(resolvedLocale);
  const minDate = min ?? null;
  const maxDate = max ?? null;
  const isControlledValue = value !== undefined;
  const [internalValue, setInternalValue] = useState<Date | null>(defaultValue ?? null);
  const resolvedValue = isControlledValue ? (value ?? null) : internalValue;

  const initialFocus = focusedDate ?? resolvedValue ?? new Date();
  const isControlledFocus = focusedDate !== undefined;
  const [internalFocus, setInternalFocus] = useState<Date>(initialFocus);
  const resolvedFocus = useMemo(
    () => (isControlledFocus ? (focusedDate ?? new Date()) : internalFocus),
    [isControlledFocus, focusedDate, internalFocus],
  );

  const setFocus = useCallback(
    (date: Date) => {
      const clamped = clampDate(date, minDate, maxDate);
      if (!isControlledFocus) setInternalFocus(clamped);
      onFocusedDateChange?.(clamped);
    },
    [isControlledFocus, minDate, maxDate, onFocusedDateChange],
  );

  const labelId = useId();
  const gridRef = useRef<HTMLDivElement | null>(null);

  // Roving focus: when resolvedFocus changes, move DOM focus to the
  // matching cell so AT users follow the keyboard.
  useEffect(() => {
    if (!gridRef.current) return;
    const cell = gridRef.current.querySelector<HTMLButtonElement>(
      `[data-iso="${formatISO(resolvedFocus)}"]`,
    );
    if (cell && document.activeElement !== cell && (autoFocus || gridRef.current.contains(document.activeElement))) {
      cell.focus();
    }
  }, [resolvedFocus, autoFocus]);

  const monthFmt = new Intl.DateTimeFormat(resolvedLocale, { month: "long", year: "numeric" });
  const weekdayFmt = new Intl.DateTimeFormat(resolvedLocale, { weekday: "narrow" });
  const monthLabel = monthFmt.format(resolvedFocus);

  const monthStart = startOfMonth(resolvedFocus);
  const offset = (monthStart.getDay() - startsOn + 7) % 7;
  const gridStart = addDays(monthStart, -offset);

  const weekdays: string[] = [];
  for (let i = 0; i < 7; i += 1) {
    weekdays.push(weekdayFmt.format(addDays(gridStart, i)));
  }

  const today = new Date();
  const days: Array<{ date: Date; iso: string; outOfMonth: boolean; disabled: boolean }> = [];
  for (let i = 0; i < WEEKS * 7; i += 1) {
    const date = addDays(gridStart, i);
    const iso = formatISO(date);
    const outOfMonth = date.getMonth() !== monthStart.getMonth();
    const disabledByRange = (minDate && date < minDate) || (maxDate && date > maxDate);
    const disabled = Boolean(disabledByRange) || Boolean(disabledDates?.(date));
    days.push({ date, iso, outOfMonth, disabled });
  }

  const select = useCallback(
    (date: Date) => {
      if ((minDate && date < minDate) || (maxDate && date > maxDate)) return;
      if (disabledDates?.(date)) return;
      if (!isControlledValue) setInternalValue(date);
      onValueChange?.(date);
      setFocus(date);
    },
    [minDate, maxDate, disabledDates, isControlledValue, onValueChange, setFocus],
  );

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    let nextFocus: Date | null = null;
    if (event.key === "ArrowLeft") nextFocus = addDays(resolvedFocus, -1);
    else if (event.key === "ArrowRight") nextFocus = addDays(resolvedFocus, 1);
    else if (event.key === "ArrowUp") nextFocus = addDays(resolvedFocus, -7);
    else if (event.key === "ArrowDown") nextFocus = addDays(resolvedFocus, 7);
    else if (event.key === "Home") {
      const dayOfWeek = (resolvedFocus.getDay() - startsOn + 7) % 7;
      nextFocus = addDays(resolvedFocus, -dayOfWeek);
    } else if (event.key === "End") {
      const dayOfWeek = (resolvedFocus.getDay() - startsOn + 7) % 7;
      nextFocus = addDays(resolvedFocus, 6 - dayOfWeek);
    } else if (event.key === "PageUp") {
      nextFocus = addMonths(resolvedFocus, event.shiftKey ? -12 : -1);
    } else if (event.key === "PageDown") {
      nextFocus = addMonths(resolvedFocus, event.shiftKey ? 12 : 1);
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      select(resolvedFocus);
      return;
    }
    if (nextFocus) {
      event.preventDefault();
      setFocus(nextFocus);
    }
  };

  return (
    <div className="calendar" aria-labelledby={labelId} role="group">
      <header className="calendar-header">
        <button
          type="button"
          className="calendar-nav"
          aria-label="Previous month"
          onClick={() => setFocus(addMonths(resolvedFocus, -1))}
        >
          <ChevronLeft size={14} aria-hidden="true" />
        </button>
        <span id={labelId} className="calendar-month" aria-live="polite">
          {label ? `${label} — ${monthLabel}` : monthLabel}
        </span>
        <button
          type="button"
          className="calendar-nav"
          aria-label="Next month"
          onClick={() => setFocus(addMonths(resolvedFocus, 1))}
        >
          <ChevronRight size={14} aria-hidden="true" />
        </button>
      </header>
      <div className="calendar-weekdays" aria-hidden="true">
        {weekdays.map((day, index) => (
          <span key={`${day}-${index}`} className="calendar-weekday">
            {day}
          </span>
        ))}
      </div>
      <div
        ref={gridRef}
        className="calendar-grid"
        role="grid"
        aria-labelledby={labelId}
        onKeyDown={onKeyDown}
      >
        {days.map(({ date, iso, outOfMonth, disabled }) => {
          const isToday = isSameDay(date, today);
          const isSelected = resolvedValue ? isSameDay(date, resolvedValue) : false;
          const isFocused = isSameDay(date, resolvedFocus);
          return (
            <button
              key={iso}
              type="button"
              role="gridcell"
              tabIndex={isFocused ? 0 : -1}
              data-iso={iso}
              data-today={isToday || undefined}
              data-selected={isSelected || undefined}
              data-out-of-month={outOfMonth || undefined}
              data-disabled={disabled || undefined}
              aria-selected={isSelected}
              aria-disabled={disabled || undefined}
              disabled={disabled}
              className="calendar-day"
              onClick={() => select(date)}
              onFocus={() => setFocus(date)}
            >
              {date.getDate()}
            </button>
          );
        })}
      </div>
    </div>
  );
}

/* ── DatePicker ───────────────────────────────────────────────────────── */

export interface DatePickerProps {
  readonly label: string;
  readonly value?: DateValue;
  readonly defaultValue?: DateValue;
  readonly onValueChange?: (value: Date | null) => void;
  readonly min?: Date | string;
  readonly max?: Date | string;
  /** Display formatter. The hidden input always emits ISO `YYYY-MM-DD`. */
  readonly format?: (date: Date, locale: string) => string;
  readonly locale?: string;
  readonly placeholder?: string;
  readonly disabled?: boolean;
  readonly name?: string;
  readonly disabledDates?: (date: Date) => boolean;
  readonly weekStartsOn?: 0 | 1;
  readonly open?: boolean;
  readonly defaultOpen?: boolean;
  readonly onOpenChange?: (open: boolean) => void;
  readonly id?: string;
  readonly trigger?: ReactNode;
}

const defaultFormat = (date: Date, locale: string): string =>
  new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(date);

export function DatePicker({
  label,
  value,
  defaultValue,
  onValueChange,
  min,
  max,
  format = defaultFormat,
  locale,
  placeholder = "Select date…",
  disabled,
  name,
  disabledDates,
  weekStartsOn,
  open,
  defaultOpen,
  onOpenChange,
  id,
  trigger,
}: DatePickerProps) {
  const fieldAttrs = useFieldAttrs() as {
    id?: string;
    "aria-describedby"?: string;
    "aria-invalid"?: true | undefined;
    "aria-required"?: true | undefined;
    required?: true | undefined;
  };
  const generatedId = useId();
  const triggerId = id ?? fieldAttrs.id ?? generatedId;
  const dialogId = `${triggerId}-popover`;
  const resolvedLocale = locale ?? (typeof navigator !== "undefined" ? navigator.language : "en-US");

  const isControlledValue = value !== undefined;
  const [internalValue, setInternalValue] = useState<Date | null>(asDate(defaultValue));
  const resolvedValue: Date | null = isControlledValue ? asDate(value) : internalValue;

  const isControlledOpen = open !== undefined;
  const [internalOpen, setInternalOpen] = useState<boolean>(defaultOpen ?? false);
  const isOpen = isControlledOpen ? Boolean(open) : internalOpen;

  const containerRef = useRef<HTMLSpanElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);

  const setOpen = useCallback(
    (next: boolean) => {
      if (!isControlledOpen) setInternalOpen(next);
      onOpenChange?.(next);
    },
    [isControlledOpen, onOpenChange],
  );

  // Outside-click + Escape close.
  useEffect(() => {
    if (!isOpen) return undefined;
    const onMouseDown = (event: MouseEvent) => {
      if (!containerRef.current) return;
      if (!containerRef.current.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    document.addEventListener("mousedown", onMouseDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onMouseDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [isOpen, setOpen]);

  const select = (next: Date) => {
    if (!isControlledValue) setInternalValue(next);
    onValueChange?.(next);
    setOpen(false);
    requestAnimationFrame(() => triggerRef.current?.focus());
  };

  const display = resolvedValue ? format(resolvedValue, resolvedLocale) : placeholder;
  const isoForForm = resolvedValue ? formatISO(resolvedValue) : "";

  return (
    <span ref={containerRef} className="datepicker">
      <button
        ref={triggerRef}
        type="button"
        id={triggerId}
        className={`datepicker-trigger ${resolvedValue ? "" : "datepicker-trigger--placeholder"}`.trim()}
        role="combobox"
        aria-label={label}
        aria-haspopup="dialog"
        aria-expanded={isOpen}
        aria-controls={dialogId}
        aria-describedby={fieldAttrs["aria-describedby"]}
        aria-invalid={fieldAttrs["aria-invalid"]}
        aria-required={fieldAttrs["aria-required"]}
        disabled={disabled}
        onClick={() => setOpen(!isOpen)}
      >
        {trigger ?? (
          <>
            <CalendarIcon size={14} aria-hidden="true" className="datepicker-icon" />
            <span className={resolvedValue ? "datepicker-value" : "datepicker-placeholder"}>{display}</span>
          </>
        )}
      </button>
      {name ? <input type="hidden" name={name} value={isoForForm} /> : null}
      {isOpen ? (
        <div
          id={dialogId}
          className="datepicker-popover"
          role="dialog"
          aria-modal="false"
          aria-label={label}
        >
          <Calendar
            value={resolvedValue}
            onValueChange={select}
            min={asDate(min) ?? undefined}
            max={asDate(max) ?? undefined}
            disabledDates={disabledDates}
            locale={resolvedLocale}
            weekStartsOn={weekStartsOn}
            label={label}
            autoFocus
          />
        </div>
      ) : null}
    </span>
  );
}
