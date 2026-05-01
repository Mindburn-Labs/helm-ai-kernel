"use client";

import {
  createContext,
  useCallback,
  useContext,
  useId,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type FormEvent,
  type KeyboardEvent,
  type ReactNode,
} from "react";

/**
 * Form primitives. Each input is dual-mode:
 *   • Pass `value` + `onChange` (or `onValueChange` / `onCheckedChange`) → controlled.
 *   • Pass only `defaultValue` (or `defaultChecked`) → uncontrolled.
 *   • Pass only `value` with no change handler → uncontrolled, seeded with
 *     that value. (Backward-compatible with the prior uncontrolled-only API.)
 *
 * `FormField` provides id, label-for, aria-describedby, aria-invalid, and
 * aria-required to every nested input via context — so consumers wire
 * accessibility once, at the field, not per-input.
 */

interface FormFieldCtx {
  readonly id: string;
  readonly describedBy?: string;
  readonly invalid: boolean;
  readonly required: boolean;
}

const FormFieldContext = createContext<FormFieldCtx | null>(null);

export interface FormFieldProps {
  readonly label: string;
  readonly hint?: string;
  readonly error?: string;
  readonly required?: boolean;
  readonly children: ReactNode;
  /**
   * When set and rendered inside a `<Form>`, auto-picks its `error`
   * from the form's validation state under this key. An explicit
   * `error` prop always wins. Use this to thread Form-level
   * errors to fields without per-field plumbing — give the nested
   * input the same `name` and the wiring is automatic.
   */
  readonly name?: string;
}

export function FormField({ label, hint, error, required = false, name, children }: FormFieldProps) {
  const id = useId();
  const formState = useContext(FormContext);
  const fromFormError =
    name && formState ? (formState.errors[name as keyof typeof formState.errors] as string | undefined) : undefined;
  const resolvedError = error ?? fromFormError;
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [hint ? hintId : null, resolvedError ? errorId : null].filter(Boolean).join(" ") || undefined;
  const ctx: FormFieldCtx = { id, describedBy, invalid: Boolean(resolvedError), required };
  return (
    <div className={`form-field ${resolvedError ? "has-error" : ""}`}>
      <label htmlFor={id} className="form-field-label">
        <span>
          {label}
          {required ? <span aria-hidden="true" className="required-mark"> *</span> : null}
        </span>
      </label>
      <FormFieldContext.Provider value={ctx}>{children}</FormFieldContext.Provider>
      {hint ? <small id={hintId}>{hint}</small> : null}
      {resolvedError ? (
        <strong id={errorId} role="alert">
          {resolvedError}
        </strong>
      ) : null}
    </div>
  );
}

/**
 * Read the surrounding `FormField`'s id/aria-describedby/aria-invalid/
 * aria-required so a custom input can wire the same a11y plumbing as the
 * built-in primitives. Returns an empty object when used outside a
 * `FormField` so consumers can render bare.
 */
export function useFieldAttrs() {
  const ctx = useContext(FormFieldContext);
  if (!ctx) return {};
  return {
    id: ctx.id,
    "aria-describedby": ctx.describedBy,
    "aria-invalid": ctx.invalid || undefined,
    "aria-required": ctx.required || undefined,
    required: ctx.required || undefined,
  } as const;
}

export type TextInputType = "text" | "email" | "url" | "tel" | "search" | "password" | "number";

export interface TextInputProps {
  readonly value?: string;
  readonly defaultValue?: string;
  readonly onChange?: (event: ChangeEvent<HTMLInputElement>) => void;
  readonly onValueChange?: (value: string) => void;
  readonly placeholder?: string;
  readonly type?: TextInputType;
  readonly disabled?: boolean;
  readonly readOnly?: boolean;
  readonly autoComplete?: string;
  readonly inputMode?: "text" | "numeric" | "decimal" | "email" | "tel" | "url" | "search" | "none";
  readonly name?: string;
  readonly maxLength?: number;
  readonly minLength?: number;
  readonly pattern?: string;
}

export function TextInput({
  value,
  defaultValue,
  onChange,
  onValueChange,
  placeholder,
  type = "text",
  disabled,
  readOnly,
  autoComplete,
  inputMode,
  name,
  maxLength,
  minLength,
  pattern,
}: TextInputProps) {
  const attrs = useFieldAttrs();
  const isControlled = onChange !== undefined || onValueChange !== undefined;
  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    onChange?.(event);
    onValueChange?.(event.currentTarget.value);
  };
  const valueProps = isControlled
    ? ({ value: value ?? "", onChange: handleChange } as const)
    : ({ defaultValue: defaultValue ?? value } as const);
  return (
    <input
      className="text-input"
      type={type}
      placeholder={placeholder}
      disabled={disabled}
      readOnly={readOnly}
      autoComplete={autoComplete}
      inputMode={inputMode}
      name={name}
      maxLength={maxLength}
      minLength={minLength}
      pattern={pattern}
      {...valueProps}
      {...attrs}
    />
  );
}

export interface TextareaFieldProps {
  readonly value?: string;
  readonly defaultValue?: string;
  readonly onChange?: (event: ChangeEvent<HTMLTextAreaElement>) => void;
  readonly onValueChange?: (value: string) => void;
  readonly placeholder?: string;
  readonly disabled?: boolean;
  readonly readOnly?: boolean;
  readonly name?: string;
  readonly rows?: number;
  readonly maxLength?: number;
  readonly minLength?: number;
}

export function TextareaField({
  value,
  defaultValue,
  onChange,
  onValueChange,
  placeholder,
  disabled,
  readOnly,
  name,
  rows = 4,
  maxLength,
  minLength,
}: TextareaFieldProps) {
  const attrs = useFieldAttrs();
  const isControlled = onChange !== undefined || onValueChange !== undefined;
  const handleChange = (event: ChangeEvent<HTMLTextAreaElement>) => {
    onChange?.(event);
    onValueChange?.(event.currentTarget.value);
  };
  const valueProps = isControlled
    ? ({ value: value ?? "", onChange: handleChange } as const)
    : ({ defaultValue: defaultValue ?? value } as const);
  return (
    <textarea
      className="textarea-input"
      placeholder={placeholder}
      disabled={disabled}
      readOnly={readOnly}
      name={name}
      rows={rows}
      maxLength={maxLength}
      minLength={minLength}
      {...valueProps}
      {...attrs}
    />
  );
}

export interface SelectFieldProps {
  readonly value?: string;
  readonly defaultValue?: string;
  readonly onChange?: (event: ChangeEvent<HTMLSelectElement>) => void;
  readonly onValueChange?: (value: string) => void;
  readonly options: readonly string[];
  readonly disabled?: boolean;
  readonly name?: string;
}

export function SelectField({
  value,
  defaultValue,
  onChange,
  onValueChange,
  options,
  disabled,
  name,
}: SelectFieldProps) {
  const attrs = useFieldAttrs();
  const isControlled = onChange !== undefined || onValueChange !== undefined;
  const handleChange = (event: ChangeEvent<HTMLSelectElement>) => {
    onChange?.(event);
    onValueChange?.(event.currentTarget.value);
  };
  const valueProps = isControlled
    ? ({ value: value ?? "", onChange: handleChange } as const)
    : ({ defaultValue: defaultValue ?? value } as const);
  return (
    <select className="select-input" disabled={disabled} name={name} {...valueProps} {...attrs}>
      {options.map((option) => (
        <option key={option} value={option}>
          {option}
        </option>
      ))}
    </select>
  );
}

export interface CheckboxFieldProps {
  readonly label: string;
  readonly checked?: boolean;
  readonly defaultChecked?: boolean;
  readonly onChange?: (event: ChangeEvent<HTMLInputElement>) => void;
  readonly onCheckedChange?: (checked: boolean) => void;
  readonly disabled?: boolean;
  readonly name?: string;
  readonly value?: string;
}

export function CheckboxField({
  label,
  checked,
  defaultChecked,
  onChange,
  onCheckedChange,
  disabled,
  name,
  value,
}: CheckboxFieldProps) {
  const isControlled = onChange !== undefined || onCheckedChange !== undefined;
  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    onChange?.(event);
    onCheckedChange?.(event.currentTarget.checked);
  };
  const checkedProps = isControlled
    ? ({ checked: checked ?? false, onChange: handleChange } as const)
    : ({ defaultChecked: defaultChecked ?? checked ?? false } as const);
  return (
    <label className="choice-field">
      <input type="checkbox" disabled={disabled} name={name} value={value} {...checkedProps} />
      <span>{label}</span>
    </label>
  );
}

export interface ToggleFieldProps {
  readonly label: string;
  readonly checked?: boolean;
  readonly defaultChecked?: boolean;
  readonly onChange?: (event: ChangeEvent<HTMLInputElement>) => void;
  readonly onCheckedChange?: (checked: boolean) => void;
  readonly disabled?: boolean;
  readonly name?: string;
}

export function ToggleField({
  label,
  checked,
  defaultChecked,
  onChange,
  onCheckedChange,
  disabled,
  name,
}: ToggleFieldProps) {
  const isControlled = onChange !== undefined || onCheckedChange !== undefined;
  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    onChange?.(event);
    onCheckedChange?.(event.currentTarget.checked);
  };
  const checkedProps = isControlled
    ? ({ checked: checked ?? false, onChange: handleChange } as const)
    : ({ defaultChecked: defaultChecked ?? checked ?? false } as const);
  return (
    <label className="toggle-field">
      <span>{label}</span>
      <input type="checkbox" role="switch" disabled={disabled} name={name} {...checkedProps} />
      <i aria-hidden="true" />
    </label>
  );
}

/* NumberInput ----------------------------------------------------------- */

export interface NumberInputProps {
  readonly value?: number | null;
  readonly defaultValue?: number | null;
  readonly onValueChange?: (value: number | null) => void;
  readonly onChange?: (event: ChangeEvent<HTMLInputElement>) => void;
  readonly min?: number;
  readonly max?: number;
  readonly step?: number;
  /** Decimal digits — also drives `inputMode` (numeric vs decimal). */
  readonly precision?: number;
  readonly prefix?: string;
  readonly suffix?: string;
  readonly stepperPosition?: "leading" | "trailing" | "none";
  readonly placeholder?: string;
  readonly disabled?: boolean;
  readonly readOnly?: boolean;
  readonly name?: string;
  readonly autoComplete?: string;
  readonly inputMode?: "numeric" | "decimal";
}

function isValidNumericDraft(draft: string, allowDecimals: boolean, allowNegative: boolean): boolean {
  if (draft === "" || draft === "-") return allowNegative || draft === "";
  // Permit one optional sign, optional integer part, optional single decimal point + fractional part.
  const pattern = allowDecimals
    ? /^-?(\d+)?(\.\d*)?$/
    : /^-?\d*$/;
  if (!pattern.test(draft)) return false;
  if (!allowNegative && draft.startsWith("-")) return false;
  return true;
}

function formatNumeric(value: number, precision: number | undefined): string {
  if (precision === undefined) return String(value);
  return value.toFixed(Math.max(0, precision));
}

function clampNumeric(value: number, min: number | undefined, max: number | undefined): number {
  let next = value;
  if (typeof min === "number" && next < min) next = min;
  if (typeof max === "number" && next > max) next = max;
  return next;
}

function roundToPrecision(value: number, precision: number | undefined): number {
  if (precision === undefined) return value;
  const factor = 10 ** Math.max(0, precision);
  return Math.round(value * factor) / factor;
}

/**
 * Numeric input with controlled+uncontrolled dual mode, clamping on blur,
 * keyboard step (ArrowUp/Down ±step, Shift× ten), and Increment/Decrement
 * buttons. Sanitizes keystrokes against a numeric grammar so the visible
 * draft can stay mid-edit (e.g. "-", "1.", "0.") without tripping on
 * `parseFloat` round-trips. Wires to FormField (id, aria-describedby,
 * aria-invalid, aria-required) and to Form's native FormData submission
 * via the standard `name` attribute.
 *
 * The committed value is `null` when the input is empty (and not
 * required) — distinct from `0`. Validation should treat `null` as
 * "not provided".
 */
export function NumberInput({
  value,
  defaultValue,
  onValueChange,
  onChange,
  min,
  max,
  step = 1,
  precision,
  prefix,
  suffix,
  stepperPosition = "trailing",
  placeholder,
  disabled,
  readOnly,
  name,
  autoComplete,
  inputMode,
}: NumberInputProps) {
  const attrs = useFieldAttrs();
  const isControlled = value !== undefined;
  const allowDecimals = precision === undefined || precision > 0;
  const allowNegative = min === undefined || min < 0;
  const resolvedInputMode = inputMode ?? (allowDecimals ? "decimal" : "numeric");

  const initialDraft = (() => {
    const seed = isControlled ? value : (defaultValue ?? value);
    if (seed === null || seed === undefined) return "";
    return formatNumeric(seed, precision);
  })();
  const [draft, setDraft] = useState<string>(initialDraft);
  const inputRef = useRef<HTMLInputElement | null>(null);

  // When controlled, mirror external value into the draft unless the user
  // is mid-edit and the parsed draft already matches. Pattern: derive state
  // during render via a stored prevValue, per
  // https://react.dev/learn/you-might-not-need-an-effect#adjusting-some-state-when-a-prop-changes
  const [prevControlledValue, setPrevControlledValue] = useState<NumberInputProps["value"]>(value);
  if (isControlled && value !== prevControlledValue) {
    setPrevControlledValue(value);
    const currentParsed = draft === "" || draft === "-" ? null : Number(draft);
    const matchesCurrent = draft !== "" && currentParsed === value;
    if (!matchesCurrent) {
      setDraft(value === null || value === undefined ? "" : formatNumeric(value, precision));
    }
  }

  const commit = useCallback((rawDraft: string): { draft: string; numeric: number | null } => {
    const trimmed = rawDraft.trim();
    if (trimmed === "" || trimmed === "-") {
      return { draft: "", numeric: null };
    }
    const parsed = Number(trimmed);
    if (Number.isNaN(parsed)) return { draft: "", numeric: null };
    const clamped = clampNumeric(parsed, min, max);
    const rounded = roundToPrecision(clamped, precision);
    return { draft: formatNumeric(rounded, precision), numeric: rounded };
  }, [min, max, precision]);

  const applyStep = useCallback((delta: number) => {
    const current = draft === "" || draft === "-" ? 0 : Number(draft);
    const tentative = (Number.isFinite(current) ? current : 0) + delta;
    const clamped = clampNumeric(tentative, min, max);
    const rounded = roundToPrecision(clamped, precision);
    const next = formatNumeric(rounded, precision);
    setDraft(next);
    onValueChange?.(rounded);
  }, [draft, min, max, precision, onValueChange]);

  const handleInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    const next = event.currentTarget.value;
    if (!isValidNumericDraft(next, allowDecimals, allowNegative)) {
      // Reject the keystroke by snapping back to the previous draft.
      event.preventDefault();
      return;
    }
    setDraft(next);
    onChange?.(event);
    // Emit a numeric callback only when the draft parses cleanly to a
    // finite number, so consumers don't see noisy mid-edit values.
    if (next === "" || next === "-") {
      onValueChange?.(null);
    } else {
      const parsed = Number(next);
      if (Number.isFinite(parsed)) onValueChange?.(parsed);
    }
  };

  const handleBlur = () => {
    const { draft: nextDraft, numeric } = commit(draft);
    setDraft(nextDraft);
    onValueChange?.(numeric);
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowUp") {
      event.preventDefault();
      applyStep(event.shiftKey ? step * 10 : step);
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      applyStep(event.shiftKey ? -step * 10 : -step);
    } else if (event.key === "Home" && typeof min === "number") {
      event.preventDefault();
      const rounded = roundToPrecision(min, precision);
      setDraft(formatNumeric(rounded, precision));
      onValueChange?.(rounded);
    } else if (event.key === "End" && typeof max === "number") {
      event.preventDefault();
      const rounded = roundToPrecision(max, precision);
      setDraft(formatNumeric(rounded, precision));
      onValueChange?.(rounded);
    }
  };

  const showSteppers = stepperPosition !== "none";
  const steppers = showSteppers ? (
    <span className="number-input-steppers" aria-hidden="true">
      <button
        type="button"
        tabIndex={-1}
        className="number-input-stepper number-input-stepper--up"
        onClick={() => {
          inputRef.current?.focus();
          applyStep(step);
        }}
        disabled={disabled || readOnly}
        aria-label="Increment"
      >
        +
      </button>
      <button
        type="button"
        tabIndex={-1}
        className="number-input-stepper number-input-stepper--down"
        onClick={() => {
          inputRef.current?.focus();
          applyStep(-step);
        }}
        disabled={disabled || readOnly}
        aria-label="Decrement"
      >
        −
      </button>
    </span>
  ) : null;

  return (
    <span className={`number-input number-input--steppers-${stepperPosition}`}>
      {stepperPosition === "leading" ? steppers : null}
      {prefix ? <span className="number-input-affix number-input-affix--prefix">{prefix}</span> : null}
      <input
        ref={inputRef}
        className="number-input-input text-input"
        type="text"
        inputMode={resolvedInputMode}
        autoComplete={autoComplete ?? "off"}
        placeholder={placeholder}
        disabled={disabled}
        readOnly={readOnly}
        name={name}
        value={draft}
        onChange={handleInputChange}
        onBlur={handleBlur}
        onKeyDown={handleKeyDown}
        {...attrs}
      />
      {suffix ? <span className="number-input-affix number-input-affix--suffix">{suffix}</span> : null}
      {stepperPosition === "trailing" ? steppers : null}
    </span>
  );
}

/* Form orchestration ---------------------------------------------------- */

export type FormValues = Record<string, FormDataEntryValue | FormDataEntryValue[]>;

export type FormErrors<TValues extends FormValues = FormValues> = Partial<
  Record<keyof TValues | string, string>
>;

/**
 * Validator signature: receives parsed form values, returns a map of
 * field-name → error message. An empty object (or `undefined`) means
 * the form is valid.
 *
 * Compatible with zod via a thin wrapper:
 *
 *     const validate = (values) => {
 *       const result = schema.safeParse(values);
 *       if (result.success) return {};
 *       return Object.fromEntries(
 *         result.error.issues.map((i) => [i.path.join("."), i.message]),
 *       );
 *     };
 */
export type FormValidator<TValues extends FormValues = FormValues> = (
  values: TValues,
) => FormErrors<TValues> | undefined;

interface FormCtx<TValues extends FormValues = FormValues> {
  readonly id: string;
  readonly errors: FormErrors<TValues>;
  readonly submitting: boolean;
  readonly setFieldError: (field: string, error: string | undefined) => void;
}

const FormContext = createContext<FormCtx | null>(null);

/**
 * Read the surrounding `<Form>`'s state. Returns `null` when used outside
 * a form (so consumers can degrade gracefully).
 */
export function useFormState<TValues extends FormValues = FormValues>() {
  return useContext(FormContext) as FormCtx<TValues> | null;
}

export interface FormProps<TValues extends FormValues = FormValues> {
  readonly children: ReactNode;
  /**
   * Called with parsed values when the form passes validation. Receives
   * the raw `FormEvent` so consumers can call `preventDefault` themselves
   * if they want — the wrapper already does that for the validation path.
   */
  readonly onSubmit: (values: TValues, event: FormEvent<HTMLFormElement>) => void | Promise<void>;
  /**
   * Optional validator. If it returns a non-empty errors map, `onSubmit`
   * is skipped, the errors are surfaced via `useFormState()` and an
   * `onValidationError` callback is fired.
   */
  readonly validate?: FormValidator<TValues>;
  readonly onValidationError?: (errors: FormErrors<TValues>) => void;
  readonly resetOnSubmit?: boolean;
  readonly noValidate?: boolean;
  readonly className?: string;
  readonly id?: string;
  /** ARIA label for the form. */
  readonly "aria-label"?: string;
}

/**
 * Lightweight `<Form>` wrapper that orchestrates submit + validation
 * without requiring controlled state on every field. Reads field values
 * from the native `FormData` on submit, runs the optional validator,
 * exposes errors via context to nested `FormField`s and `FormSummary`.
 *
 * Pairs with the existing field primitives (TextInput, SelectField,
 * CheckboxField, ToggleField) which already accept a `name` prop —
 * just give each field a `name` and the wrapper does the rest.
 *
 * For schema-first validation (zod / yup / ajv), pass an adapter via
 * the `validate` prop — see the `FormValidator` jsdoc for an example.
 */
export function Form<TValues extends FormValues = FormValues>({
  children,
  onSubmit,
  validate,
  onValidationError,
  resetOnSubmit = false,
  noValidate = true,
  className,
  id,
  "aria-label": ariaLabel,
}: FormProps<TValues>) {
  const generatedId = useId();
  const formId = id ?? generatedId;
  const [errors, setErrors] = useState<FormErrors<TValues>>({});
  const [submitting, setSubmitting] = useState(false);

  const setFieldError = useCallback((field: string, error: string | undefined) => {
    setErrors((current) => {
      const next = { ...current };
      if (error === undefined) delete next[field];
      else next[field as keyof typeof next] = error as never;
      return next;
    });
  }, []);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const values = Object.fromEntries(formData.entries()) as TValues;

    if (validate) {
      const validationErrors = validate(values) ?? {};
      const hasErrors = Object.keys(validationErrors).length > 0;
      setErrors(validationErrors);
      if (hasErrors) {
        onValidationError?.(validationErrors);
        return;
      }
    } else {
      setErrors({});
    }

    setSubmitting(true);
    try {
      await onSubmit(values, event);
      if (resetOnSubmit) event.currentTarget.reset();
    } finally {
      setSubmitting(false);
    }
  };

  const ctx = useMemo<FormCtx<TValues>>(
    () => ({ id: formId, errors, submitting, setFieldError }),
    [formId, errors, submitting, setFieldError],
  );

  return (
    <FormContext.Provider value={ctx as FormCtx}>
      <form
        id={formId}
        className={className}
        aria-label={ariaLabel}
        noValidate={noValidate}
        onSubmit={handleSubmit}
      >
        {children}
      </form>
    </FormContext.Provider>
  );
}

export interface FormSummaryProps {
  readonly title?: string;
  readonly className?: string;
}

/**
 * Renders a roll-up of all form-level errors as an `aria-live="assertive"`
 * region. Consumers drop it inside `<Form>` (typically near the submit
 * button) and it auto-announces when validation fails.
 *
 * Returns null when there are no errors, so it's safe to render
 * unconditionally.
 */
export function FormSummary({ title = "Please fix the following:", className }: FormSummaryProps) {
  const ctx = useFormState();
  const entries = ctx ? Object.entries(ctx.errors) : [];
  if (entries.length === 0) return null;
  return (
    <div className={["form-summary", className].filter(Boolean).join(" ")} role="alert" aria-live="assertive">
      <strong>{title}</strong>
      <ul>
        {entries.map(([field, message]) => (
          <li key={field}>
            <span className="form-summary-field">{field}</span>
            <span className="form-summary-message">{message}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
