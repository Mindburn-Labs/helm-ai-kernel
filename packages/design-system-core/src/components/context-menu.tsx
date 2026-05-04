"use client";

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type MouseEvent,
  type CSSProperties,
  type ReactNode,
} from "react";
import type { MenuItem } from "./primitives";

/**
 * ContextMenu — right-click / `Shift+F10` triggered popup menu rendered
 * at cursor coordinates. Distinct from `MenuButton` (click-on-trigger)
 * and `Popover` (generic floating panel).
 *
 * Wraps an arbitrary region; on `contextmenu` (right-click) or
 * `Shift+F10` keyboard event, opens a menu at the cursor / focused-
 * element rect. `Escape` or outside-click closes.
 *
 * ARIA: popup is `role="menu"` with each item `role="menuitem"`.
 * Keyboard: ArrowDown/Up moves focus, Home/End jump, Enter activates.
 */

export interface ContextMenuProps {
  readonly items: readonly MenuItem[];
  readonly children: ReactNode;
  readonly onOpenChange?: (open: boolean) => void;
  readonly disabled?: boolean;
  readonly className?: string;
}

interface Position {
  readonly x: number;
  readonly y: number;
}

export function ContextMenu({ items, children, onOpenChange, disabled, className }: ContextMenuProps) {
  const [open, setOpenState] = useState(false);
  const [position, setPosition] = useState<Position>({ x: 0, y: 0 });
  const [activeIndex, setActiveIndex] = useState(0);
  const menuRef = useRef<HTMLDivElement | null>(null);

  const setOpen = useCallback(
    (next: boolean) => {
      setOpenState(next);
      onOpenChange?.(next);
    },
    [onOpenChange],
  );

  const onContextMenu = (event: MouseEvent<HTMLDivElement>) => {
    if (disabled) return;
    event.preventDefault();
    setPosition({ x: event.clientX, y: event.clientY });
    setActiveIndex(0);
    setOpen(true);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (disabled) return;
    if (event.shiftKey && event.key === "F10") {
      event.preventDefault();
      const target = event.currentTarget.getBoundingClientRect();
      setPosition({ x: target.left + 10, y: target.top + 10 });
      setActiveIndex(0);
      setOpen(true);
    }
  };

  useEffect(() => {
    if (!open) return undefined;
    const onDocMouseDown = (event: globalThis.MouseEvent) => {
      if (!menuRef.current) return;
      if (!menuRef.current.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setOpen(false);
      } else if (event.key === "ArrowDown") {
        event.preventDefault();
        setActiveIndex((i) => Math.min(items.length - 1, i + 1));
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        setActiveIndex((i) => Math.max(0, i - 1));
      } else if (event.key === "Home") {
        event.preventDefault();
        setActiveIndex(0);
      } else if (event.key === "End") {
        event.preventDefault();
        setActiveIndex(items.length - 1);
      } else if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        const item = items[activeIndex];
        if (item && !item.disabled) {
          item.onSelect?.();
          setOpen(false);
        }
      }
    };
    document.addEventListener("mousedown", onDocMouseDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocMouseDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, items, activeIndex, setOpen]);

  const menuStyle = {
    "--helm-context-menu-x": `${position.x}px`,
    "--helm-context-menu-y": `${position.y}px`,
  } as CSSProperties;

  return (
    <div
      className={["context-menu-region", className].filter(Boolean).join(" ")}
      onContextMenu={onContextMenu}
      onKeyDown={onKeyDown}
    >
      {children}
      {open ? (
        <div
          ref={menuRef}
          role="menu"
          className="context-menu-popup"
          style={menuStyle}
          aria-orientation="vertical"
        >
          {items.map((item, index) => (
            <button
              key={item.id ?? `${index}-${typeof item.label === "string" ? item.label : "item"}`}
              type="button"
              role="menuitem"
              tabIndex={index === activeIndex ? 0 : -1}
              data-active={index === activeIndex || undefined}
              aria-disabled={item.disabled || undefined}
              disabled={item.disabled}
              className="context-menu-item"
              onMouseEnter={() => setActiveIndex(index)}
              onClick={() => {
                if (item.disabled) return;
                item.onSelect?.();
                setOpen(false);
              }}
            >
              {item.label}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}
