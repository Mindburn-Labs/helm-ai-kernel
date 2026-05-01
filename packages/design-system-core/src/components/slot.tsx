"use client";

import {
  cloneElement,
  isValidElement,
  type CSSProperties,
  type ReactElement,
  type ReactNode,
  type Ref,
} from "react";

type AnyProps = Record<string, unknown>;

/**
 * Compose multiple refs into one. Call all in sequence; supports both
 * function refs and ref objects. Used by `Slot` to forward to both the
 * consumer's child ref and the parent's ref.
 */
export function mergeRefs<T>(...refs: ReadonlyArray<Ref<T> | undefined | null>) {
  return (value: T | null) => {
    for (const ref of refs) {
      if (typeof ref === "function") ref(value);
      else if (ref != null) (ref as { current: T | null }).current = value;
    }
  };
}

/**
 * Compose multiple event handlers — invoke in slot-then-child order. Each
 * runs regardless of whether earlier handlers called preventDefault, so
 * consumers should check `event.defaultPrevented` if they want to opt out.
 */
function composeHandlers<E>(
  ...handlers: ReadonlyArray<((event: E) => void) | undefined>
): (event: E) => void {
  return (event: E) => {
    for (const handler of handlers) handler?.(event);
  };
}

/**
 * Merge slot props onto child props following Radix's convention:
 *   - `className`: concatenate (slot first, then child)
 *   - `style`: shallow-merge (slot first, child overrides on key clash)
 *   - event handlers (`on…`): compose (slot first, then child)
 *   - everything else: child wins so the consumer's intent is preserved
 */
function mergeProps(slotProps: AnyProps, childProps: AnyProps): AnyProps {
  const merged: AnyProps = { ...childProps };
  for (const key of Object.keys(slotProps)) {
    const slotValue = slotProps[key];
    const childValue = childProps[key];
    if (key === "className") {
      merged[key] = [slotValue, childValue].filter(Boolean).join(" ");
    } else if (key === "style") {
      merged[key] = {
        ...((slotValue as CSSProperties | undefined) ?? {}),
        ...((childValue as CSSProperties | undefined) ?? {}),
      };
    } else if (key.startsWith("on") && typeof slotValue === "function") {
      merged[key] = composeHandlers(
        slotValue as (event: unknown) => void,
        childValue as ((event: unknown) => void) | undefined,
      );
    } else if (slotValue !== undefined && childValue === undefined) {
      merged[key] = slotValue;
    }
  }
  return merged;
}

export interface SlotProps {
  readonly children?: ReactNode;
  readonly ref?: Ref<HTMLElement>;
}

/**
 * Radix-style `Slot` — clones the single React element child and merges
 * the slot's props (className, style, event handlers, ref) onto it.
 *
 * Used to implement the `asChild` pattern: a wrapper component delegates
 * rendering to the consumer's element while still applying its own
 * styling and behaviour. Example:
 *
 * ```tsx
 * <Button asChild>
 *   <a href="/policies">Open policies</a>
 * </Button>
 * ```
 *
 * renders as `<a href="/policies" class="helm-button …">Open policies</a>`,
 * letting the consumer keep the right semantics (link vs button) without
 * forking the styled component.
 *
 * If `children` is not a valid React element, the slot renders nothing.
 */
export function Slot({ children, ref, ...slotProps }: SlotProps & AnyProps) {
  if (!isValidElement(children)) return null;
  const child = children as ReactElement<AnyProps & { ref?: Ref<HTMLElement> }>;
  const merged = mergeProps(slotProps, child.props);
  // React 19 surfaces refs as a regular prop on `props.ref`. Pre-19
  // forwardRef children expose it on the element itself; cover both.
  const legacyRef = (child as unknown as { ref?: Ref<HTMLElement> }).ref;
  const childRef = child.props.ref ?? legacyRef;
  merged.ref = mergeRefs(ref, childRef);
  return cloneElement(child, merged as AnyProps);
}
