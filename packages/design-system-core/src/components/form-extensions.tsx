"use client";

import {
  useCallback,
  useId,
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent,
  type ReactNode,
} from "react";
import { useFieldAttrs } from "./forms";

/* FieldArray ─────────────────────────────────────────────────────────── */

export interface FieldArrayHandle<T> {
  readonly items: ReadonlyArray<{ readonly key: string; readonly value: T }>;
  /** Stable keyed name for the i-th sub-field, e.g. `recipients.0.email`. */
  readonly fieldName: (index: number, subKey?: string) => string;
  readonly add: (value: T) => void;
  readonly remove: (index: number) => void;
  readonly move: (from: number, to: number) => void;
  readonly clear: () => void;
}

export interface FieldArrayProps<T> {
  /** Submit-time prefix; sub-fields are named `${name}.${index}.${subKey}`. */
  readonly name: string;
  readonly defaultValue?: ReadonlyArray<T>;
  readonly children: (handle: FieldArrayHandle<T>) => ReactNode;
}

/**
 * Render-prop primitive that owns an ordered array of items with stable
 * keys. Consumers render the items themselves and wire each sub-field's
 * `name` via `handle.fieldName(index, subKey)` so native FormData
 * submission produces a flat dotted-key payload.
 *
 * Pairs with `<Form>`'s validate function — the validator receives the
 * flat key map; consumers reconstruct the array shape from it.
 */
interface FieldArrayState<T> {
  readonly items: ReadonlyArray<{ key: string; value: T }>;
  readonly nextSeed: number;
}

export function FieldArray<T>({ name, defaultValue = [], children }: FieldArrayProps<T>) {
  const [state, setState] = useState<FieldArrayState<T>>(() => ({
    items: defaultValue.map((value, index) => ({ key: `${name}-${index}`, value })),
    nextSeed: defaultValue.length,
  }));
  const { items } = state;

  const fieldName = useCallback(
    (index: number, subKey?: string) => (subKey ? `${name}.${index}.${subKey}` : `${name}.${index}`),
    [name],
  );

  const add = useCallback(
    (value: T) => {
      setState((current) => ({
        items: [...current.items, { key: `${name}-${current.nextSeed}`, value }],
        nextSeed: current.nextSeed + 1,
      }));
    },
    [name],
  );

  const remove = useCallback((index: number) => {
    setState((current) => ({
      ...current,
      items: current.items.filter((_, i) => i !== index),
    }));
  }, []);

  const move = useCallback((from: number, to: number) => {
    setState((current) => {
      if (from < 0 || from >= current.items.length) return current;
      if (to < 0 || to >= current.items.length) return current;
      const next = current.items.slice();
      const [moved] = next.splice(from, 1);
      if (moved) next.splice(to, 0, moved);
      return { ...current, items: next };
    });
  }, []);

  const clear = useCallback(() => {
    setState((current) => ({ ...current, items: [] }));
  }, []);

  const handle: FieldArrayHandle<T> = { items, fieldName, add, remove, move, clear };

  return <>{children(handle)}</>;
}

/* FileField ──────────────────────────────────────────────────────────── */

export interface FileFieldProps {
  readonly value?: ReadonlyArray<File>;
  readonly defaultValue?: ReadonlyArray<File>;
  readonly onValueChange?: (files: ReadonlyArray<File>) => void;
  readonly onChange?: (event: ChangeEvent<HTMLInputElement>) => void;
  readonly accept?: string;
  readonly multiple?: boolean;
  /** Maximum byte size per file. Files larger than this fire `onError`. */
  readonly maxSize?: number;
  readonly onError?: (error: { code: "size" | "type"; file: File }) => void;
  readonly disabled?: boolean;
  readonly name?: string;
  readonly placeholder?: string;
  readonly hint?: string;
}

/**
 * File picker with drag/drop support. Wires to FormField via
 * `useFieldAttrs()`; works as a controlled or uncontrolled field.
 *
 * Drop zone: the wrapper accepts dragged files and calls `onValueChange`
 * with a filtered list (respecting `accept` and `maxSize`). Visual
 * state is reflected via the `data-dragging` attribute on the wrapper.
 */
export function FileField({
  value,
  defaultValue,
  onValueChange,
  onChange,
  accept,
  multiple = false,
  maxSize,
  onError,
  disabled,
  name,
  placeholder = "Choose files or drop here",
  hint,
}: FileFieldProps) {
  const attrs = useFieldAttrs();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const isControlled = value !== undefined;
  const [internal, setInternal] = useState<ReadonlyArray<File>>(defaultValue ?? []);
  const files: ReadonlyArray<File> = isControlled ? (value ?? []) : internal;
  const [dragging, setDragging] = useState(false);
  const dropId = useId();

  const filterAndCommit = useCallback(
    (incoming: FileList | ReadonlyArray<File>) => {
      const list = Array.isArray(incoming)
        ? (incoming as ReadonlyArray<File>)
        : Array.from(incoming as FileList);
      const accepted: File[] = [];
      for (const file of list) {
        if (typeof maxSize === "number" && file.size > maxSize) {
          onError?.({ code: "size", file });
          continue;
        }
        if (accept) {
          const acceptList = accept.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
          const matches = acceptList.some((spec) => {
            if (spec.startsWith(".")) return file.name.toLowerCase().endsWith(spec);
            if (spec.endsWith("/*")) return file.type.toLowerCase().startsWith(spec.slice(0, -1));
            return file.type.toLowerCase() === spec;
          });
          if (acceptList.length > 0 && !matches) {
            onError?.({ code: "type", file });
            continue;
          }
        }
        accepted.push(file);
      }
      const next = multiple ? accepted : accepted.slice(0, 1);
      if (!isControlled) setInternal(next);
      onValueChange?.(next);
    },
    [accept, maxSize, multiple, onError, isControlled, onValueChange],
  );

  const onInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    onChange?.(event);
    if (event.currentTarget.files) filterAndCommit(event.currentTarget.files);
  };

  const onDragOver = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    if (!disabled) setDragging(true);
  };
  const onDragLeave = () => setDragging(false);
  const onDrop = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    setDragging(false);
    if (disabled) return;
    if (event.dataTransfer.files) filterAndCommit(event.dataTransfer.files);
  };

  return (
    <div className="file-field" data-dragging={dragging || undefined}>
      <label
        htmlFor={dropId}
        className="file-field-dropzone"
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
      >
        <span className="file-field-placeholder">
          {files.length === 0
            ? placeholder
            : `${files.length} file${files.length === 1 ? "" : "s"} selected`}
        </span>
        {hint ? <span className="file-field-hint">{hint}</span> : null}
        <input
          ref={inputRef}
          id={dropId}
          type="file"
          className="file-field-input"
          accept={accept}
          multiple={multiple}
          disabled={disabled}
          name={name}
          onChange={onInputChange}
          {...attrs}
        />
      </label>
      {files.length > 0 ? (
        <ul className="file-field-list" aria-label="Selected files">
          {files.map((file, index) => (
            <li key={`${file.name}-${index}`} className="file-field-list-item">
              <span className="file-field-name">{file.name}</span>
              <span className="file-field-size">{Math.ceil(file.size / 1024)} KB</span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
