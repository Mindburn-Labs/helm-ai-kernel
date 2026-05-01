"use client";

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactNode,
} from "react";

/**
 * HoverCard — hover- or focus-triggered floating panel for rich content
 * (avatar, link, description). Distinct from `Tooltip` (text-only, short
 * delay, role="tooltip") and `Popover` (click-triggered, modal-ish).
 *
 * - Open delay (default 300ms) and close delay (default 200ms) prevent
 *   flicker when the cursor crosses the gap between trigger and content.
 * - Pointer entering the content cancels the close timer; leaving the
 *   content schedules a close.
 * - Focus on the trigger opens the card; Escape closes and returns
 *   focus to the trigger.
 *
 * ARIA:
 *   - The trigger gets `aria-describedby` pointing at the content.
 *   - The content uses `role="tooltip"` so AT software treats it as
 *     supplementary; consumers needing a different role can wrap their
 *     own element inside.
 */

export type HoverCardSide = "top" | "bottom" | "start" | "end";
export type HoverCardAlign = "start" | "center" | "end";

export interface HoverCardProps {
  readonly trigger: ReactNode;
  readonly children: ReactNode;
  readonly openDelay?: number;
  readonly closeDelay?: number;
  readonly side?: HoverCardSide;
  readonly align?: HoverCardAlign;
  readonly open?: boolean;
  readonly defaultOpen?: boolean;
  readonly onOpenChange?: (open: boolean) => void;
  readonly className?: string;
}

export function HoverCard({
  trigger,
  children,
  openDelay = 300,
  closeDelay = 200,
  side = "bottom",
  align = "start",
  open: controlledOpen,
  defaultOpen = false,
  onOpenChange,
  className,
}: HoverCardProps) {
  const id = useId();
  const [internalOpen, setInternalOpen] = useState(defaultOpen);
  const isControlled = controlledOpen !== undefined;
  const open = isControlled ? controlledOpen : internalOpen;
  const triggerRef = useRef<HTMLSpanElement | null>(null);
  const openTimerRef = useRef<number | null>(null);
  const closeTimerRef = useRef<number | null>(null);

  const clearTimers = useCallback(() => {
    if (openTimerRef.current !== null) {
      window.clearTimeout(openTimerRef.current);
      openTimerRef.current = null;
    }
    if (closeTimerRef.current !== null) {
      window.clearTimeout(closeTimerRef.current);
      closeTimerRef.current = null;
    }
  }, []);

  const setOpen = useCallback(
    (next: boolean) => {
      if (!isControlled) setInternalOpen(next);
      onOpenChange?.(next);
    },
    [isControlled, onOpenChange],
  );

  const scheduleOpen = useCallback(() => {
    clearTimers();
    openTimerRef.current = window.setTimeout(() => setOpen(true), openDelay);
  }, [clearTimers, openDelay, setOpen]);

  const scheduleClose = useCallback(() => {
    clearTimers();
    closeTimerRef.current = window.setTimeout(() => setOpen(false), closeDelay);
  }, [clearTimers, closeDelay, setOpen]);

  useEffect(() => () => clearTimers(), [clearTimers]);

  useEffect(() => {
    if (!open) return undefined;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        clearTimers();
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, clearTimers, setOpen]);

  return (
    <span
      className={["hover-card-root", className].filter(Boolean).join(" ")}
      data-side={side}
      data-align={align}
      data-open={open || undefined}
    >
      <span
        ref={triggerRef}
        className="hover-card-trigger"
        aria-describedby={open ? id : undefined}
        tabIndex={0}
        onMouseEnter={scheduleOpen}
        onMouseLeave={scheduleClose}
        onFocus={scheduleOpen}
        onBlur={scheduleClose}
      >
        {trigger}
      </span>
      {open ? (
        <span
          id={id}
          role="tooltip"
          className="hover-card-content"
          onMouseEnter={clearTimers}
          onMouseLeave={scheduleClose}
        >
          {children}
        </span>
      ) : null}
    </span>
  );
}
