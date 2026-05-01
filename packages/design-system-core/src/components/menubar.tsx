"use client";

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";

/**
 * MenuBar — top-level menu bar with optional nested submenus
 * (file/edit/view-style). Distinct from `MenuButton` (single trigger,
 * single panel) and `ContextMenu` (cursor-positioned, no top-level bar).
 *
 * Two-level keyboard map:
 *   Top level:
 *     ArrowLeft / ArrowRight  — move between menus.
 *     ArrowDown / Enter       — open the active menu.
 *     Escape                  — close the open menu.
 *   Inside a menu:
 *     ArrowUp / ArrowDown     — move between items.
 *     ArrowLeft               — close current submenu (or move to prev top menu).
 *     ArrowRight              — open submenu (when item.submenu is set) or
 *                               move to next top menu.
 *     Enter                   — activate leaf item.
 *     Escape                  — close the entire menubar.
 *
 * ARIA: `role="menubar"` on root, `role="menu"` on each panel,
 * `role="menuitem"` on items; items with submenus get
 * `aria-haspopup="menu"` and `aria-expanded`.
 */

export interface MenuBarItem {
  readonly id: string;
  readonly label: ReactNode;
  readonly onSelect?: () => void;
  readonly disabled?: boolean;
  readonly destructive?: boolean;
  readonly shortcut?: string;
  readonly submenu?: readonly MenuBarItem[];
}

export interface MenuBarMenu {
  readonly id: string;
  readonly label: string;
  readonly items: readonly MenuBarItem[];
}

export interface MenuBarProps {
  readonly label: string;
  readonly menus: readonly MenuBarMenu[];
  readonly onOpenChange?: (menuId: string | null) => void;
  readonly className?: string;
}

interface SubmenuState {
  readonly itemId: string;
  readonly index: number;
}

export function MenuBar({ label, menus, onOpenChange, className }: MenuBarProps) {
  const [activeMenu, setActiveMenu] = useState<string | null>(null);
  const [activeItemIndex, setActiveItemIndex] = useState(0);
  const [openSubmenu, setOpenSubmenu] = useState<SubmenuState | null>(null);
  const [submenuItemIndex, setSubmenuItemIndex] = useState(0);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const triggerRefs = useRef<Map<string, HTMLButtonElement | null>>(new Map());
  const baseId = useId();

  const setOpenMenu = useCallback(
    (next: string | null) => {
      setActiveMenu(next);
      setActiveItemIndex(0);
      setOpenSubmenu(null);
      setSubmenuItemIndex(0);
      onOpenChange?.(next);
    },
    [onOpenChange],
  );

  const closeAll = useCallback(() => setOpenMenu(null), [setOpenMenu]);

  useEffect(() => {
    if (activeMenu === null) return undefined;
    const onClick = (event: globalThis.MouseEvent) => {
      if (!rootRef.current) return;
      if (!rootRef.current.contains(event.target as Node)) closeAll();
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [activeMenu, closeAll]);

  const onTopKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const idx = Math.max(
      0,
      menus.findIndex((m) => m.id === activeMenu),
    );
    if (event.key === "ArrowRight") {
      event.preventDefault();
      const next = menus[(idx + 1) % menus.length];
      if (next) {
        setOpenMenu(next.id);
        triggerRefs.current.get(next.id)?.focus();
      }
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      const next = menus[(idx - 1 + menus.length) % menus.length];
      if (next) {
        setOpenMenu(next.id);
        triggerRefs.current.get(next.id)?.focus();
      }
    } else if (event.key === "Escape") {
      event.preventDefault();
      closeAll();
    }
  };

  const onMenuKeyDown = (
    event: KeyboardEvent<HTMLDivElement>,
    items: readonly MenuBarItem[],
  ) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveItemIndex((i) => Math.min(items.length - 1, i + 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveItemIndex((i) => Math.max(0, i - 1));
    } else if (event.key === "Home") {
      event.preventDefault();
      setActiveItemIndex(0);
    } else if (event.key === "End") {
      event.preventDefault();
      setActiveItemIndex(items.length - 1);
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      const item = items[activeItemIndex];
      if (!item || item.disabled) return;
      if (item.submenu) {
        setOpenSubmenu({ itemId: item.id, index: activeItemIndex });
        setSubmenuItemIndex(0);
      } else {
        item.onSelect?.();
        closeAll();
      }
    } else if (event.key === "ArrowRight") {
      event.preventDefault();
      const item = items[activeItemIndex];
      if (item?.submenu && !item.disabled) {
        setOpenSubmenu({ itemId: item.id, index: activeItemIndex });
        setSubmenuItemIndex(0);
      } else {
        const idx = Math.max(0, menus.findIndex((m) => m.id === activeMenu));
        const next = menus[(idx + 1) % menus.length];
        if (next) {
          setOpenMenu(next.id);
          triggerRefs.current.get(next.id)?.focus();
        }
      }
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      if (openSubmenu) {
        setOpenSubmenu(null);
      } else {
        const idx = Math.max(0, menus.findIndex((m) => m.id === activeMenu));
        const next = menus[(idx - 1 + menus.length) % menus.length];
        if (next) {
          setOpenMenu(next.id);
          triggerRefs.current.get(next.id)?.focus();
        }
      }
    } else if (event.key === "Escape") {
      event.preventDefault();
      closeAll();
    }
  };

  const onSubmenuKeyDown = (
    event: KeyboardEvent<HTMLDivElement>,
    submenuItems: readonly MenuBarItem[],
  ) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setSubmenuItemIndex((i) => Math.min(submenuItems.length - 1, i + 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setSubmenuItemIndex((i) => Math.max(0, i - 1));
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      const item = submenuItems[submenuItemIndex];
      if (!item || item.disabled) return;
      item.onSelect?.();
      closeAll();
    } else if (event.key === "ArrowLeft" || event.key === "Escape") {
      event.preventDefault();
      setOpenSubmenu(null);
    }
  };

  return (
    <div
      ref={rootRef}
      className={["menubar", className].filter(Boolean).join(" ")}
      role="menubar"
      aria-label={label}
      onKeyDown={onTopKeyDown}
    >
      {menus.map((menu) => {
        const isOpen = activeMenu === menu.id;
        return (
          <div key={menu.id} className="menubar-menu" data-open={isOpen || undefined}>
            <button
              ref={(node) => {
                triggerRefs.current.set(menu.id, node);
              }}
              type="button"
              className="menubar-trigger"
              role="menuitem"
              aria-haspopup="menu"
              aria-expanded={isOpen}
              aria-controls={`${baseId}-${menu.id}`}
              onClick={() => setOpenMenu(isOpen ? null : menu.id)}
              onMouseEnter={() => {
                if (activeMenu !== null) setOpenMenu(menu.id);
              }}
            >
              {menu.label}
            </button>
            {isOpen ? (
              <div
                id={`${baseId}-${menu.id}`}
                role="menu"
                className="menubar-panel"
                aria-orientation="vertical"
                onKeyDown={(event) => onMenuKeyDown(event, menu.items)}
                tabIndex={-1}
              >
                {menu.items.map((item, index) => {
                  const submenuOpen =
                    openSubmenu?.itemId === item.id && index === openSubmenu.index;
                  return (
                    <div key={item.id} className="menubar-item-wrap">
                      <button
                        type="button"
                        role="menuitem"
                        className={`menubar-item${item.destructive ? " is-destructive" : ""}`}
                        tabIndex={index === activeItemIndex ? 0 : -1}
                        data-active={index === activeItemIndex || undefined}
                        aria-disabled={item.disabled || undefined}
                        aria-haspopup={item.submenu ? "menu" : undefined}
                        aria-expanded={item.submenu ? submenuOpen : undefined}
                        disabled={item.disabled}
                        onMouseEnter={() => setActiveItemIndex(index)}
                        onClick={() => {
                          if (item.disabled) return;
                          if (item.submenu) {
                            setOpenSubmenu(submenuOpen ? null : { itemId: item.id, index });
                            setSubmenuItemIndex(0);
                          } else {
                            item.onSelect?.();
                            closeAll();
                          }
                        }}
                      >
                        <span className="menubar-item-label">{item.label}</span>
                        {item.shortcut ? (
                          <kbd className="menubar-item-shortcut">{item.shortcut}</kbd>
                        ) : null}
                        {item.submenu ? <span className="menubar-item-arrow">›</span> : null}
                      </button>
                      {item.submenu && submenuOpen ? (
                        <div
                          role="menu"
                          className="menubar-submenu"
                          aria-orientation="vertical"
                          onKeyDown={(event) => onSubmenuKeyDown(event, item.submenu ?? [])}
                          tabIndex={-1}
                        >
                          {item.submenu.map((sub, subIndex) => (
                            <button
                              key={sub.id}
                              type="button"
                              role="menuitem"
                              className={`menubar-item${sub.destructive ? " is-destructive" : ""}`}
                              tabIndex={subIndex === submenuItemIndex ? 0 : -1}
                              data-active={subIndex === submenuItemIndex || undefined}
                              aria-disabled={sub.disabled || undefined}
                              disabled={sub.disabled}
                              onMouseEnter={() => setSubmenuItemIndex(subIndex)}
                              onClick={() => {
                                if (sub.disabled) return;
                                sub.onSelect?.();
                                closeAll();
                              }}
                            >
                              <span className="menubar-item-label">{sub.label}</span>
                              {sub.shortcut ? (
                                <kbd className="menubar-item-shortcut">{sub.shortcut}</kbd>
                              ) : null}
                            </button>
                          ))}
                        </div>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
