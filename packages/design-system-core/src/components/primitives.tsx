"use client";

import {
  type ChangeEvent,
  type KeyboardEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
} from "react";
import { ChevronDown, MoreHorizontal } from "lucide-react";
import { Tooltip } from "./core";
import { Slot } from "./slot";

function useControlledState<TValue>({
  value,
  defaultValue,
  fallback,
  onChange,
}: {
  readonly value?: TValue;
  readonly defaultValue?: TValue;
  readonly fallback: TValue;
  readonly onChange?: (value: TValue) => void;
}) {
  const [internalValue, setInternalValue] = useState(defaultValue ?? fallback);
  const resolvedValue = value ?? internalValue;
  const setValue = useCallback((nextValue: TValue) => {
    if (value === undefined) setInternalValue(nextValue);
    onChange?.(nextValue);
  }, [onChange, value]);
  return [resolvedValue, setValue] as const;
}

export interface IconButtonProps {
  readonly label: string;
  readonly icon: ReactNode;
  readonly tooltip?: string;
  readonly pressed?: boolean;
  readonly disabled?: boolean;
  readonly type?: "button" | "submit" | "reset";
  readonly onClick?: () => void;
  /**
   * Render via `Slot` instead of `<button>` — clones the consumer's single
   * child element (typically `<a>` or a router link) and merges IconButton's
   * className + aria onto it. The `icon` prop is ignored when `asChild` is
   * true; the consumer's child element is the entire content.
   */
  readonly asChild?: boolean;
  readonly children?: ReactNode;
}

export function IconButton({
  label,
  icon,
  tooltip,
  pressed,
  disabled,
  type = "button",
  onClick,
  asChild = false,
  children,
}: IconButtonProps) {
  const className = `icon-button ${pressed ? "icon-button--active" : ""}`.trim();
  const trigger = asChild ? (
    <Slot
      className={className}
      aria-label={label}
      aria-pressed={pressed}
      aria-disabled={disabled || undefined}
      data-disabled={disabled || undefined}
      onClick={onClick}
    >
      {children}
    </Slot>
  ) : (
    <button
      type={type}
      className={className}
      aria-label={label}
      aria-pressed={pressed}
      disabled={disabled}
      onClick={onClick}
    >
      {icon}
    </button>
  );
  return tooltip ? <Tooltip label={tooltip}>{trigger}</Tooltip> : trigger;
}

export interface SeparatorProps {
  readonly orientation?: "horizontal" | "vertical";
  readonly decorative?: boolean;
  readonly label?: string;
}

export function Separator({ orientation = "horizontal", decorative = true, label }: SeparatorProps) {
  return (
    <div
      className={`separator separator--${orientation}`}
      role={decorative ? "none" : "separator"}
      aria-orientation={decorative ? undefined : orientation}
      aria-label={decorative ? undefined : label}
    />
  );
}

export interface BreadcrumbItem {
  readonly label: string;
  readonly href?: string;
  readonly current?: boolean;
  readonly onClick?: () => void;
}

export function Breadcrumbs({ items, label = "Breadcrumb" }: { readonly items: readonly BreadcrumbItem[]; readonly label?: string }) {
  return (
    <nav className="breadcrumbs" aria-label={label}>
      <ol>
        {items.map((item, index) => {
          const isCurrent = item.current || index === items.length - 1;
          return (
            <li key={`${item.label}-${index}`}>
              {item.href && !isCurrent ? (
                <a href={item.href} onClick={item.onClick}>{item.label}</a>
              ) : item.onClick && !isCurrent ? (
                <button type="button" onClick={item.onClick}>{item.label}</button>
              ) : (
                <span aria-current={isCurrent ? "page" : undefined}>{item.label}</span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

export function Toolbar({ label, children }: { readonly label: string; readonly children: ReactNode }) {
  return (
    <div className="toolbar" role="toolbar" aria-label={label}>
      {children}
    </div>
  );
}

export interface DisclosureProps {
  readonly title: ReactNode;
  readonly children: ReactNode;
  readonly open?: boolean;
  readonly defaultOpen?: boolean;
  readonly onOpenChange?: (open: boolean) => void;
}

export function Disclosure({ title, children, open, defaultOpen = false, onOpenChange }: DisclosureProps) {
  const id = useId();
  const [isOpen, setIsOpen] = useControlledState({
    value: open,
    defaultValue: defaultOpen,
    fallback: false,
    onChange: onOpenChange,
  });
  return (
    <section className="disclosure">
      <button type="button" className="disclosure-trigger" aria-expanded={isOpen} aria-controls={id} onClick={() => setIsOpen(!isOpen)}>
        <span>{title}</span>
        <ChevronDown size={14} aria-hidden="true" />
      </button>
      <div id={id} className="disclosure-panel" hidden={!isOpen}>
        {children}
      </div>
    </section>
  );
}

export interface AccordionItem {
  readonly id: string;
  readonly title: ReactNode;
  readonly children: ReactNode;
  readonly disabled?: boolean;
}

export interface AccordionProps {
  readonly items: readonly AccordionItem[];
  readonly multiple?: boolean;
  readonly value?: string | readonly string[];
  readonly defaultValue?: string | readonly string[];
  readonly onValueChange?: (value: string | readonly string[]) => void;
}

function valueToSet(value: string | readonly string[] | undefined): Set<string> {
  if (value === undefined || value === "") return new Set();
  if (typeof value === "string") return new Set([value]);
  return new Set(value);
}

export function Accordion({ items, multiple = false, value, defaultValue, onValueChange }: AccordionProps) {
  const [openValue, setOpenValue] = useControlledState({
    value,
    defaultValue,
    fallback: multiple ? [] : "",
    onChange: onValueChange,
  });
  const openItems = valueToSet(openValue);
  const setItemOpen = (id: string) => {
    const next = new Set(openItems);
    if (next.has(id)) next.delete(id);
    else {
      if (!multiple) next.clear();
      next.add(id);
    }
    setOpenValue(multiple ? [...next] : [...next][0] ?? "");
  };
  return (
    <div className="accordion">
      {items.map((item) => {
        const isOpen = openItems.has(item.id);
        const panelId = `${item.id}-panel`;
        const triggerId = `${item.id}-trigger`;
        return (
          <section key={item.id} className="accordion-item">
            <button
              id={triggerId}
              type="button"
              className="accordion-trigger"
              aria-expanded={isOpen}
              aria-controls={panelId}
              disabled={item.disabled}
              onClick={() => setItemOpen(item.id)}
            >
              <span>{item.title}</span>
              <ChevronDown size={14} aria-hidden="true" />
            </button>
            <div id={panelId} className="accordion-panel" role="region" aria-labelledby={triggerId} hidden={!isOpen}>
              {item.children}
            </div>
          </section>
        );
      })}
    </div>
  );
}

export interface PopoverProps {
  readonly label: string;
  readonly trigger?: ReactNode;
  readonly title?: string;
  readonly children: ReactNode;
  readonly open?: boolean;
  readonly defaultOpen?: boolean;
  readonly onOpenChange?: (open: boolean) => void;
}

export function Popover({ label, trigger, title, children, open, defaultOpen = false, onOpenChange }: PopoverProps) {
  const id = useId();
  const rootRef = useRef<HTMLDivElement | null>(null);
  const [isOpen, setIsOpen] = useControlledState({
    value: open,
    defaultValue: defaultOpen,
    fallback: false,
    onChange: onOpenChange,
  });

  useEffect(() => {
    if (!isOpen) return undefined;
    const onPointerDown = (event: PointerEvent) => {
      if (rootRef.current?.contains(event.target as Node)) return;
      setIsOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [isOpen, setIsOpen]);

  return (
    <div ref={rootRef} className="popover-root">
      <button type="button" className="popover-trigger" aria-expanded={isOpen} aria-controls={id} onClick={() => setIsOpen(!isOpen)}>
        {trigger ?? label}
      </button>
      <div
        id={id}
        className="popover-content"
        role="dialog"
        aria-label={title ?? label}
        hidden={!isOpen}
        onKeyDown={(event) => {
          if (event.key === "Escape") setIsOpen(false);
        }}
      >
        {title ? <strong>{title}</strong> : null}
        {children}
      </div>
    </div>
  );
}

export interface MenuItem {
  readonly id: string;
  readonly label: string;
  readonly onSelect: () => void;
  readonly disabled?: boolean;
  readonly destructive?: boolean;
}

export function MenuButton({ label, items }: { readonly label: string; readonly items: readonly MenuItem[] }) {
  const id = useId();
  const rootRef = useRef<HTMLDivElement | null>(null);
  const itemRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (event: PointerEvent) => {
      if (rootRef.current?.contains(event.target as Node)) return;
      setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [open]);

  const focusItem = (index: number) => {
    setActiveIndex(index);
    window.requestAnimationFrame(() => itemRefs.current[index]?.focus());
  };
  const selectableItems = items.map((item, index) => ({ item, index })).filter(({ item }) => !item.disabled);
  const firstSelectableIndex = selectableItems[0]?.index ?? 0;
  const lastSelectableIndex = selectableItems.at(-1)?.index ?? items.length - 1;

  const onMenuKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
      return;
    }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const currentSelectableIndex = selectableItems.findIndex(({ index }) => index === activeIndex);
      const nextSelectableIndex =
        event.key === "ArrowDown"
          ? Math.min(selectableItems.length - 1, currentSelectableIndex + 1)
          : Math.max(0, currentSelectableIndex - 1);
      const next = selectableItems[nextSelectableIndex]?.index ?? firstSelectableIndex;
      focusItem(next);
    }
  };

  return (
    <div ref={rootRef} className="menu-root" onKeyDown={onMenuKeyDown}>
      <button
        type="button"
        className="menu-trigger"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => {
          const nextOpen = !open;
          setOpen(nextOpen);
          if (nextOpen) focusItem(firstSelectableIndex);
        }}
      >
        <span>{label}</span>
        <MoreHorizontal size={14} aria-hidden="true" />
      </button>
      <div id={id} className="menu-content" role="menu" hidden={!open}>
        {items.map((item, index) => (
          <button
            key={item.id}
            ref={(node) => { itemRefs.current[index] = node; }}
            type="button"
            role="menuitem"
            className={`menu-item ${item.destructive ? "menu-item--destructive" : ""}`.trim()}
            disabled={item.disabled}
            tabIndex={index === activeIndex ? 0 : -1}
            onMouseEnter={() => setActiveIndex(index)}
            onClick={() => {
              item.onSelect();
              setOpen(false);
            }}
          >
            {item.label}
          </button>
        ))}
      </div>
      <span className="sr-only" aria-live="polite">{open ? `Menu opened. ${lastSelectableIndex + 1} items available.` : ""}</span>
    </div>
  );
}

export interface RadioOption {
  readonly value: string;
  readonly label: string;
  readonly hint?: string;
  readonly disabled?: boolean;
}

export interface RadioGroupProps {
  readonly legend: string;
  readonly options: readonly RadioOption[];
  readonly value?: string;
  readonly defaultValue?: string;
  readonly onValueChange?: (value: string) => void;
  readonly name?: string;
  readonly disabled?: boolean;
}

export function RadioGroup({ legend, options, value, defaultValue, onValueChange, name, disabled }: RadioGroupProps) {
  const generatedName = useId();
  const [selectedValue, setSelectedValue] = useControlledState({
    value,
    defaultValue,
    fallback: options[0]?.value ?? "",
    onChange: onValueChange,
  });
  const groupName = name ?? generatedName;
  return (
    <fieldset className="radio-group" disabled={disabled}>
      <legend>{legend}</legend>
      {options.map((option) => (
        <label key={option.value} className="radio-card">
          <input
            type="radio"
            name={groupName}
            value={option.value}
            checked={selectedValue === option.value}
            disabled={option.disabled}
            onChange={() => setSelectedValue(option.value)}
          />
          <span>
            <strong>{option.label}</strong>
            {option.hint ? <small>{option.hint}</small> : null}
          </span>
        </label>
      ))}
    </fieldset>
  );
}

export interface SliderFieldProps {
  readonly label: string;
  readonly value?: number;
  readonly defaultValue?: number;
  readonly onValueChange?: (value: number) => void;
  readonly min?: number;
  readonly max?: number;
  readonly step?: number;
  readonly disabled?: boolean;
  readonly output?: (value: number) => string;
}

export function SliderField({
  label,
  value,
  defaultValue,
  onValueChange,
  min = 0,
  max = 100,
  step = 1,
  disabled,
  output = (currentValue) => String(currentValue),
}: SliderFieldProps) {
  const id = useId();
  const [currentValue, setCurrentValue] = useControlledState({
    value,
    defaultValue,
    fallback: min,
    onChange: onValueChange,
  });
  const onChange = (event: ChangeEvent<HTMLInputElement>) => setCurrentValue(Number(event.currentTarget.value));
  return (
    <div className="slider-field">
      <label htmlFor={id}>{label}</label>
      <div>
        <input id={id} type="range" min={min} max={max} step={step} value={currentValue} disabled={disabled} onChange={onChange} />
        <output htmlFor={id}>{output(currentValue)}</output>
      </div>
    </div>
  );
}

/* Combobox -------------------------------------------------------------- */

export interface ComboboxOption {
  readonly value: string;
  readonly label: string;
  readonly hint?: string;
  readonly disabled?: boolean;
}

export interface ComboboxProps {
  /** Visible label, also used as the input's accessible name. */
  readonly label: string;
  readonly options: readonly ComboboxOption[];
  /** Selected option value (controlled). */
  readonly value?: string;
  readonly defaultValue?: string;
  readonly onValueChange?: (value: string) => void;
  readonly placeholder?: string;
  /** Shown when query filters out all options. */
  readonly emptyLabel?: string;
  readonly disabled?: boolean;
  /**
   * If `false`, options are always visible regardless of query — useful for
   * fixed-list selects. Default `true` (filter as the user types).
   */
  readonly autoFilter?: boolean;
  readonly name?: string;
}

/**
 * Single-select combobox with a filterable listbox popup. ARIA-correct:
 * input has `role="combobox"` + `aria-expanded` + `aria-controls` +
 * `aria-activedescendant`; popup has `role="listbox"` with each row
 * `role="option"` + `aria-selected`.
 *
 * Keyboard:
 *   ArrowDown / ArrowUp — move highlight, opens listbox if closed
 *   Home / End — jump to first / last enabled option
 *   Enter — select highlighted option, close
 *   Escape — close without selecting; restore query to last selection
 *   Tab — close listbox (focus moves out naturally)
 *
 * Click outside the trigger or listbox closes the popup.
 *
 * For multi-select or async/remote options, compose the trigger and
 * listbox manually rather than reaching for this primitive.
 */
export function Combobox({
  label,
  options,
  value,
  defaultValue,
  onValueChange,
  placeholder,
  emptyLabel = "No matches",
  disabled = false,
  autoFilter = true,
  name,
}: ComboboxProps) {
  const inputId = useId();
  const listboxId = `${inputId}-listbox`;
  const [selectedValue, setSelectedValue] = useControlledState<string | undefined>({
    value,
    defaultValue,
    fallback: undefined,
    onChange: onValueChange as ((next: string | undefined) => void) | undefined,
  });
  const selectedOption = options.find((opt) => opt.value === selectedValue);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState(selectedOption?.label ?? "");
  const [rawActiveIndex, setActiveIndex] = useState(0);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const listboxRef = useRef<HTMLUListElement | null>(null);

  // Reset query when the popover closes (or when the external selection
  // changes while closed). Derive-during-render pattern using stored prev
  // values, per https://react.dev/learn/you-might-not-need-an-effect.
  const currentLabel = selectedOption?.label;
  const [prevOpen, setPrevOpen] = useState(open);
  const [prevSelectedLabel, setPrevSelectedLabel] = useState(currentLabel);
  if (open !== prevOpen || currentLabel !== prevSelectedLabel) {
    setPrevOpen(open);
    setPrevSelectedLabel(currentLabel);
    if (!open) setQuery(currentLabel ?? "");
  }

  const filtered = autoFilter && query
    ? options.filter((opt) => opt.label.toLowerCase().includes(query.toLowerCase()))
    : options;

  // Clamp activeIndex into the filtered range. Derived during render — the
  // clamped value is what consumers use; setActiveIndex drives raw state
  // updates from keyboard/click events.
  const activeIndex = filtered.length === 0
    ? 0
    : Math.min(rawActiveIndex, filtered.length - 1);

  // Close on outside click.
  useEffect(() => {
    if (!open) return undefined;
    const onDocumentMouseDown = (event: MouseEvent) => {
      if (!containerRef.current) return;
      if (!containerRef.current.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDocumentMouseDown);
    return () => document.removeEventListener("mousedown", onDocumentMouseDown);
  }, [open]);

  function nextEnabledIndex(from: number, direction: 1 | -1): number {
    if (filtered.length === 0) return 0;
    let index = from;
    for (let step = 0; step < filtered.length; step += 1) {
      index = (index + direction + filtered.length) % filtered.length;
      if (!filtered[index]?.disabled) return index;
    }
    return from;
  }

  function commit(option: ComboboxOption) {
    if (option.disabled) return;
    setSelectedValue(option.value);
    setQuery(option.label);
    setOpen(false);
  }

  const onInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    setQuery(event.currentTarget.value);
    setActiveIndex(0);
    if (!open) setOpen(true);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      if (!open) {
        setOpen(true);
        return;
      }
      setActiveIndex((current) => nextEnabledIndex(current, 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      if (!open) {
        setOpen(true);
        return;
      }
      setActiveIndex((current) => nextEnabledIndex(current, -1));
    } else if (event.key === "Home") {
      if (!open) return;
      event.preventDefault();
      setActiveIndex(nextEnabledIndex(filtered.length, 1));
    } else if (event.key === "End") {
      if (!open) return;
      event.preventDefault();
      setActiveIndex(nextEnabledIndex(-1, -1));
    } else if (event.key === "Enter") {
      if (!open) return;
      const option = filtered[activeIndex];
      if (option) {
        event.preventDefault();
        commit(option);
      }
    } else if (event.key === "Escape") {
      if (!open) return;
      event.preventDefault();
      setOpen(false);
      setQuery(selectedOption?.label ?? "");
    } else if (event.key === "Tab") {
      if (open) setOpen(false);
    }
  };

  const activeOptionId = open && filtered.length > 0 ? `${listboxId}-option-${activeIndex}` : undefined;

  return (
    <div className="combobox" ref={containerRef}>
      <label htmlFor={inputId} className="combobox-label">
        {label}
      </label>
      <input
        id={inputId}
        name={name}
        type="text"
        className="combobox-input"
        role="combobox"
        autoComplete="off"
        aria-expanded={open}
        aria-controls={listboxId}
        aria-activedescendant={activeOptionId}
        aria-autocomplete="list"
        placeholder={placeholder}
        disabled={disabled}
        value={query}
        onFocus={() => {
          if (!disabled) setOpen(true);
        }}
        onChange={onInputChange}
        onKeyDown={onKeyDown}
      />
      {open ? (
        <ul ref={listboxRef} id={listboxId} className="combobox-listbox" role="listbox" aria-label={label}>
          {filtered.length === 0 ? (
            <li className="combobox-empty" role="status">
              {emptyLabel}
            </li>
          ) : (
            filtered.map((option, index) => {
              const optionId = `${listboxId}-option-${index}`;
              const isActive = index === activeIndex;
              const isSelected = option.value === selectedValue;
              return (
                <li
                  key={option.value}
                  id={optionId}
                  role="option"
                  aria-selected={isSelected}
                  aria-disabled={option.disabled || undefined}
                  data-active={isActive || undefined}
                  className="combobox-option"
                  onMouseDown={(event) => {
                    event.preventDefault();
                    commit(option);
                  }}
                  onMouseEnter={() => setActiveIndex(index)}
                >
                  <span className="combobox-option-label">{option.label}</span>
                  {option.hint ? <span className="combobox-option-hint">{option.hint}</span> : null}
                </li>
              );
            })
          )}
        </ul>
      ) : null}
    </div>
  );
}
