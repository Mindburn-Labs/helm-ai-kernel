"use client";

import {
  Activity,
  AlertTriangle,
  Archive,
  Bell,
  CalendarClock,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Clipboard,
  Copy,
  FileJson,
  Filter,
  Gauge,
  KeyRound,
  ListChecks,
  Loader2,
  Lock,
  MoreHorizontal,
  RefreshCw,
  Search,
  ShieldCheck,
  Square,
  SlidersHorizontal,
  Terminal,
  X,
} from "lucide-react";

import {
  Component,
  type ComponentType,
  type ErrorInfo,
  type KeyboardEvent,
  type ReactNode,
  type Ref,
  type RefObject,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  ENVIRONMENT_SEMANTICS,
  RISK_SEMANTICS,
  VERDICT_SEMANTICS,
  VERIFICATION_SEMANTICS,
  type Density,
  type EnvironmentState,
  type HelmSemanticState,
  type Intensity,
  type Mode,
  type PermissionState,
  type RailState,
  type RiskState,
  type VerdictState,
  type VerificationState,
  labelForState,
  railForState,
} from "../state/semantics";
import { Slot } from "./slot";
import { assertRailPresent } from "../state/rail-guard";

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "textarea:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

function getFocusableElements(container: HTMLElement | null): HTMLElement[] {
  if (!container) return [];
  return [...container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)].filter((element) => {
    const style = window.getComputedStyle(element);
    return style.display !== "none" && style.visibility !== "hidden";
  });
}

interface ErrorBoundaryProps {
  readonly children: ReactNode;
  readonly fallback?: (error: Error, reset: () => void) => ReactNode;
}

interface ErrorBoundaryState {
  readonly error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  override state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  override componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[HELM ErrorBoundary]", error, info.componentStack);
  }

  reset = () => this.setState({ error: null });

  override render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    if (this.props.fallback) return this.props.fallback(error, this.reset);
    return (
      <div className="error-boundary" role="alert" aria-live="assertive">
        <h2>Something failed in the console.</h2>
        <p className="error-boundary-message">{error.message || "Unknown error"}</p>
        <button type="button" className="helm-button helm-button--secondary helm-button--md" onClick={this.reset}>
          Reset
        </button>
      </div>
    );
  }
}

export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  });
  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return undefined;
    const mql = window.matchMedia("(prefers-reduced-motion: reduce)");
    const handler = (event: MediaQueryListEvent) => setReduced(event.matches);
    if (typeof mql.addEventListener === "function") {
      mql.addEventListener("change", handler);
      return () => mql.removeEventListener("change", handler);
    }
    mql.addListener(handler);
    return () => mql.removeListener(handler);
  }, []);
  return reduced;
}

function useDialogFocusTrap(open: boolean, dialogRef: RefObject<HTMLElement | null>, onClose: () => void) {
  const previousFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return undefined;
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = dialogRef.current;

    window.requestAnimationFrame(() => {
      const first = getFocusableElements(dialog)[0] ?? dialog;
      first?.focus();
    });

    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab" || !dialog) return;
      const focusable = getFocusableElements(dialog);
      if (!focusable.length) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable.at(-1);
      if (!first || !last) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      window.requestAnimationFrame(() => previousFocusRef.current?.focus());
    };
  }, [dialogRef, onClose, open]);
}

export type ButtonVariant =
  | "primary"
  | "secondary"
  | "ghost"
  | "danger"
  | "approve"
  | "deny"
  | "escalate"
  | "proof"
  | "terminal";
export type ButtonSize = "sm" | "md" | "lg";

export interface ButtonProps {
  readonly ref?: Ref<HTMLButtonElement>;
  readonly variant?: ButtonVariant;
  readonly size?: ButtonSize;
  readonly children: ReactNode;
  readonly leading?: ReactNode;
  readonly trailing?: ReactNode;
  readonly disabled?: boolean;
  readonly type?: "button" | "submit" | "reset";
  readonly "aria-label"?: string;
  readonly onClick?: () => void;
  /**
   * Render via `Slot` instead of `<button>` — clones the single child
   * element and applies Button's classes / handlers to it. Lets consumers
   * preserve the right semantics for their case (e.g. `<a>` or a router
   * Link) while keeping the styled visual contract.
   *
   * When `asChild` is true, `leading` and `trailing` are ignored — the
   * child element is the entire content. Compose icons manually inside
   * the child if you need them.
   */
  readonly asChild?: boolean;
}

export function Button({
  ref,
  variant = "secondary",
  size = "md",
  children,
  leading,
  trailing,
  disabled,
  type = "button",
  "aria-label": ariaLabel,
  onClick,
  asChild = false,
}: ButtonProps) {
  const className = `helm-button helm-button--${variant} helm-button--${size}`;
  if (asChild) {
    return (
      <Slot
        ref={ref as Ref<HTMLElement>}
        className={className}
        aria-label={ariaLabel}
        aria-disabled={disabled || undefined}
        data-disabled={disabled || undefined}
        onClick={onClick}
      >
        {children}
      </Slot>
    );
  }
  return (
    <button ref={ref} type={type} className={className} disabled={disabled} aria-label={ariaLabel} onClick={onClick}>
      {leading ? <span className="button-icon">{leading}</span> : null}
      <span>{children}</span>
      {trailing ? <span className="button-icon">{trailing}</span> : null}
    </button>
  );
}

export interface BoundaryRailProps {
  readonly state: RailState;
  readonly intensity?: Intensity;
  readonly className?: string;
}

export function BoundaryRail({ state, intensity = "active", className = "" }: BoundaryRailProps) {
  return <span aria-hidden="true" className={`boundary-rail rail--${state} rail-intensity--${intensity} ${className}`.trim()} />;
}

export interface BadgeProps {
  readonly state?: HelmSemanticState;
  readonly label?: string;
  readonly tone?: "neutral" | "oss" | "commercial" | "proof" | "env" | "risk";
  readonly intensity?: Intensity;
  readonly dot?: boolean;
  /**
   * Render via `Slot` instead of `<span>`, cloning the consumer's child
   * element (typically `<a>` or a router link) and applying Badge's
   * className. The `dot`, `label`, and `state`-derived label are
   * ignored — the child element is the entire content.
   */
  readonly asChild?: boolean;
  readonly children?: ReactNode;
}

export function Badge({
  state = "historical",
  label,
  tone = "neutral",
  intensity = "active",
  dot = false,
  asChild = false,
  children,
}: BadgeProps) {
  const rail = railForState(state);
  const className = `helm-badge badge-tone--${tone} rail-text--${rail} badge-intensity--${intensity}`;
  if (asChild) {
    return <Slot className={className}>{children}</Slot>;
  }
  return (
    <span className={className}>
      {dot ? <span className={`badge-dot rail-bg--${rail}`} aria-hidden="true" /> : null}
      {label ?? labelForState(state)}
    </span>
  );
}

export function VerdictBadge({ state, intensity = "active" }: { readonly state: VerdictState; readonly intensity?: Intensity }) {
  const spec = VERDICT_SEMANTICS[state];
  return (
    <span className={`verdict-badge rail-text--${spec.rail} badge-intensity--${intensity}`} aria-label={`Verdict ${spec.label}. ${spec.description}`}>
      <BoundaryRail state={spec.rail} intensity={intensity} />
      {spec.label}
    </span>
  );
}

export function VerificationStatus({ state, label }: { readonly state: VerificationState; readonly label?: string }) {
  const spec = VERIFICATION_SEMANTICS[state];
  const Icon = state === "verified" || state === "exported" ? CheckCircle2 : state === "failed" ? X : state === "pending" ? Loader2 : Archive;
  return (
    <span className={`verification-status rail-text--${spec.rail}`} aria-label={`${spec.label}. ${spec.description}`}>
      <Icon size={13} strokeWidth={1.8} aria-hidden="true" />
      {label ?? spec.label}
    </span>
  );
}

export function EnvironmentBadge({ env }: { readonly env: EnvironmentState }) {
  const spec = ENVIRONMENT_SEMANTICS[env];
  return <Badge state={env} label={spec.label} tone="env" dot />;
}

export function RiskBadge({ risk }: { readonly risk: RiskState }) {
  const spec = RISK_SEMANTICS[risk];
  return <Badge state={risk} label={spec.label} tone="risk" />;
}

export interface HashTextProps {
  readonly value: string;
  readonly label?: string;
  readonly kind?: "hash" | "signature" | "receipt" | "policy";
  readonly truncate?: boolean;
}

export function HashText({ value, label, kind = "hash", truncate = true }: HashTextProps) {
  const [copied, setCopied] = useState(false);
  const visible = truncate && value.length > 22 ? `${value.slice(0, 12)}...${value.slice(-6)}` : value;
  const liveId = useId();
  const toast = useContext(ToastContext);
  const copy = async () => {
    try {
      if (!navigator.clipboard) throw new Error("Clipboard API unavailable in this browser context.");
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 900);
    } catch (error) {
      toast?.push({
        title: `Could not copy ${kind}`,
        detail: error instanceof Error ? error.message : "Browser blocked clipboard access.",
        tone: "failed",
      });
    }
  };
  return (
    <span className={`hash-text hash-text--${kind}`}>
      {label ? <span className="meta-label">{label}</span> : null}
      <code title={value}>{visible}</code>
      <Tooltip label={copied ? "Copied" : "Copy"}>
        <button className="icon-button" type="button" aria-label={`Copy ${kind} ${value}`} aria-describedby={liveId} onClick={copy}>
          {copied ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
        </button>
      </Tooltip>
      <span id={liveId} className="sr-only" aria-live="polite">
        {copied ? `${kind} copied` : ""}
      </span>
    </span>
  );
}

export interface PanelProps {
  readonly title?: string;
  readonly kicker?: string;
  readonly actions?: ReactNode;
  readonly children: ReactNode;
  readonly priority?: "primary" | "secondary" | "muted";
  readonly rail?: RailState;
}

export function Panel({ title, kicker, actions, children, priority = "secondary", rail }: PanelProps) {
  if (priority === "primary" && !rail) {
    assertRailPresent("verified", false, `Panel("${title ?? kicker ?? "primary"}")`);
  }
  return (
    <section className={`panel panel--${priority} ${rail ? `panel--rail rail-border--${rail}` : ""}`.trim()}>
      {title || kicker || actions ? (
        <header className="panel-header">
          <div>
            {kicker ? <div className="kicker">{kicker}</div> : null}
            {title ? <h2>{title}</h2> : null}
          </div>
          {actions ? <div className="panel-actions">{actions}</div> : null}
        </header>
      ) : null}
      <div className="panel-body">{children}</div>
    </section>
  );
}

export interface TooltipProps {
  readonly label: string;
  readonly children: ReactNode;
  /**
   * When true, merge `aria-describedby` directly onto the consumer's
   * single child element instead of wrapping it in a `<span>`. Use this
   * when the wrapper span would interfere with surrounding flex/grid
   * layout or with the trigger's own `aria-*` wiring.
   */
  readonly asChild?: boolean;
}

export function Tooltip({ label, children, asChild = false }: TooltipProps) {
  const id = useId();
  return (
    <span className="tooltip-root">
      {asChild ? (
        <Slot aria-describedby={id}>{children}</Slot>
      ) : (
        <span aria-describedby={id}>{children}</span>
      )}
      <span id={id} role="tooltip" className="tooltip-content">
        {label}
      </span>
    </span>
  );
}

export interface TabOption<TValue extends string> {
  readonly value: TValue;
  readonly label: string;
  readonly badge?: string;
}

export interface TabsProps<TValue extends string> {
  readonly value: TValue;
  readonly options: readonly TabOption<TValue>[];
  readonly onChange: (value: TValue) => void;
  readonly label: string;
  readonly variant?: "page" | "inline";
}

export function Tabs<TValue extends string>({ value, options, onChange, label, variant = "inline" }: TabsProps<TValue>) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const activeIndex = Math.max(0, options.findIndex((option) => option.value === value));
    const last = options.length - 1;
    const nextIndex =
      event.key === "ArrowRight" ? Math.min(last, activeIndex + 1) :
      event.key === "ArrowLeft" ? Math.max(0, activeIndex - 1) :
      event.key === "Home" ? 0 :
      event.key === "End" ? last :
      activeIndex;
    if (nextIndex === activeIndex && event.key !== "Home" && event.key !== "End") return;
    if (!["ArrowRight", "ArrowLeft", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const next = options[nextIndex];
    if (!next) return;
    onChange(next.value);
    window.requestAnimationFrame(() => refs.current[nextIndex]?.focus());
  };
  return (
    <div className={`tabs tabs--${variant}`} role="tablist" aria-label={label} onKeyDown={onKeyDown}>
      {options.map((option, index) => (
        <button
          key={option.value}
          ref={(node) => { refs.current[index] = node; }}
          type="button"
          role="tab"
          aria-selected={value === option.value}
          tabIndex={value === option.value ? 0 : -1}
          className={`tab-button ${value === option.value ? "is-active" : ""}`}
          onClick={() => onChange(option.value)}
        >
          <span>{option.label}</span>
          {option.badge ? <span className="tab-badge">{option.badge}</span> : null}
        </button>
      ))}
    </div>
  );
}

export type DrawerSize = "sm" | "md" | "lg";

export interface DrawerProps {
  readonly open: boolean;
  readonly title: string;
  readonly children: ReactNode;
  readonly onClose: () => void;
  readonly size?: DrawerSize;
}

export function Drawer({ open, title, children, onClose, size = "md" }: DrawerProps) {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  useDialogFocusTrap(open, dialogRef, onClose);

  useEffect(() => {
    if (!open) return undefined;
    const body = document.body;
    const previousOverflow = body.style.overflow;
    const previousPaddingRight = body.style.paddingRight;
    const scrollbar = window.innerWidth - document.documentElement.clientWidth;
    body.style.overflow = "hidden";
    if (scrollbar > 0) body.style.paddingRight = `${scrollbar}px`;
    return () => {
      body.style.overflow = previousOverflow;
      body.style.paddingRight = previousPaddingRight;
    };
  }, [open]);

  if (!open) return null;
  return (
    <div className="drawer-backdrop" role="presentation" onMouseDown={onClose}>
      <div
        ref={dialogRef}
        className={`drawer drawer--${size}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="drawer-header">
          <h2>{title}</h2>
          <button className="icon-button" type="button" aria-label="Close drawer" onClick={onClose}>
            <X size={15} aria-hidden="true" />
          </button>
        </header>
        <div className="drawer-body">{children}</div>
      </div>
    </div>
  );
}

export type DialogSize = "sm" | "md" | "lg";

export interface DialogProps {
  readonly open: boolean;
  readonly title: string;
  readonly description?: string;
  readonly children?: ReactNode;
  readonly footer?: ReactNode;
  readonly onClose: () => void;
  readonly size?: DialogSize;
  /**
   * Dismiss when the user clicks the backdrop. Default `true`. Set `false`
   * for destructive confirmations where an accidental click should not
   * cancel the action — pair with `showCloseButton={false}` and use
   * `AlertDialog` instead.
   */
  readonly closeOnBackdrop?: boolean;
  /** Show the X close button in the header. Default `true`. */
  readonly showCloseButton?: boolean;
  /** ARIA role. Use `"alertdialog"` for destructive flows; default `"dialog"`. */
  readonly role?: "dialog" | "alertdialog";
}

/**
 * Centered modal dialog. Focus-trapped, ESC-dismissible, restores focus to
 * the previously-focused element on close. Pair with the `Drawer` primitive
 * for side-anchored overlays.
 *
 * The backdrop scroll-locks the body and dismisses the dialog on click
 * unless `closeOnBackdrop={false}`. Title is wired via `aria-labelledby`;
 * if `description` is set, the body is given an `aria-describedby` binding.
 */
export function Dialog({
  open,
  title,
  description,
  children,
  footer,
  onClose,
  size = "md",
  closeOnBackdrop = true,
  showCloseButton = true,
  role = "dialog",
}: DialogProps) {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const titleId = useId();
  const descriptionId = useId();
  useDialogFocusTrap(open, dialogRef, onClose);

  useEffect(() => {
    if (!open) return undefined;
    const body = document.body;
    const previousOverflow = body.style.overflow;
    const previousPaddingRight = body.style.paddingRight;
    const scrollbar = window.innerWidth - document.documentElement.clientWidth;
    body.style.overflow = "hidden";
    if (scrollbar > 0) body.style.paddingRight = `${scrollbar}px`;
    return () => {
      body.style.overflow = previousOverflow;
      body.style.paddingRight = previousPaddingRight;
    };
  }, [open]);

  if (!open) return null;
  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={closeOnBackdrop ? onClose : undefined}>
      <div
        ref={dialogRef}
        className={`dialog dialog--${size}`}
        role={role}
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        tabIndex={-1}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="dialog-header">
          <div className="dialog-header-copy">
            <h2 id={titleId}>{title}</h2>
            {description ? (
              <p id={descriptionId} className="dialog-description">
                {description}
              </p>
            ) : null}
          </div>
          {showCloseButton ? (
            <button className="icon-button" type="button" aria-label="Close" onClick={onClose}>
              <X size={15} aria-hidden="true" />
            </button>
          ) : null}
        </header>
        {children ? <div className="dialog-body">{children}</div> : null}
        {footer ? <footer className="dialog-footer">{footer}</footer> : null}
      </div>
    </div>
  );
}

export type AlertDialogIntent = "deny" | "danger" | "escalate" | "primary";

export interface AlertDialogProps {
  readonly open: boolean;
  readonly title: string;
  readonly description: string;
  readonly confirmLabel: string;
  readonly cancelLabel?: string;
  readonly intent?: AlertDialogIntent;
  readonly onConfirm: () => void;
  readonly onCancel: () => void;
  /** When true, both buttons are disabled (e.g. while a request is in flight). */
  readonly busy?: boolean;
}

/**
 * Destructive-action confirmation dialog. Uses `role="alertdialog"` so
 * assistive tech announces the prompt assertively. Backdrop is non-dismissive
 * by default and the close button is suppressed — the only paths out are
 * the explicit confirm / cancel buttons.
 */
export function AlertDialog({
  open,
  title,
  description,
  confirmLabel,
  cancelLabel = "Cancel",
  intent = "deny",
  onConfirm,
  onCancel,
  busy = false,
}: AlertDialogProps) {
  const confirmVariant: ButtonVariant =
    intent === "danger" || intent === "deny"
      ? "deny"
      : intent === "escalate"
        ? "escalate"
        : "primary";
  return (
    <Dialog
      open={open}
      title={title}
      description={description}
      onClose={onCancel}
      size="sm"
      closeOnBackdrop={false}
      showCloseButton={false}
      role="alertdialog"
      footer={
        <>
          <Button variant="ghost" size="md" onClick={onCancel} disabled={busy}>
            {cancelLabel}
          </Button>
          <Button variant={confirmVariant} size="md" onClick={onConfirm} disabled={busy}>
            {confirmLabel}
          </Button>
        </>
      }
    />
  );
}

export function EmptyState({ title, body, action }: { readonly title: string; readonly body: string; readonly action?: ReactNode }) {
  return (
    <div className="empty-state">
      <Square size={18} aria-hidden="true" />
      <div>
        <h3>{title}</h3>
        <p>{body}</p>
      </div>
      {action ? <div className="empty-actions">{action}</div> : null}
    </div>
  );
}

export function LoadingState({ label = 'Loading…' }: { readonly label?: string }) {
  return (
    <div className="empty-state">
      <Loader2 className="animate-spin" size={18} aria-hidden="true" />
      <div>
        <p>{label}</p>
      </div>
    </div>
  );
}

export function ErrorState({ title, error, retry }: { readonly title: string; readonly error: unknown; readonly retry?: () => void }) {
  const description = error instanceof Error ? error.message : 'The service did not return a usable response.';
  return (
    <div className="empty-state error">
      <AlertTriangle size={18} aria-hidden="true" />
      <div>
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
      {retry ? <div className="empty-actions"><Button onClick={retry}>Retry</Button></div> : null}
    </div>
  );
}

export function StatusRow({
  state,
  label,
  detail,
}: {
  readonly state: HelmSemanticState;
  readonly label?: string;
  readonly detail?: string;
}) {
  const rail = railForState(state);
  const semanticLabel = labelForState(state);
  const rowLabel = label && label !== semanticLabel ? label : undefined;
  return (
    <div className={`status-row rail-border--${rail}`}>
      <Badge state={state} label={semanticLabel} dot />
      {rowLabel || detail ? (
        <span className="status-copy">
          {rowLabel ? <span className="status-label">{rowLabel}</span> : null}
          {detail ? <span className="status-detail">{detail}</span> : null}
        </span>
      ) : null}
    </div>
  );
}

export function MetricTile({
  label,
  value,
  detail,
  state = "historical",
  trend,
}: {
  readonly label: string;
  readonly value: string;
  readonly detail?: string;
  readonly state?: HelmSemanticState;
  readonly trend?: string;
}) {
  const rail = railForState(state);
  return (
    <article className={`metric-tile rail-border--${rail}`}>
      <div className="metric-head">
        <span>{label}</span>
        <Gauge size={14} aria-hidden="true" />
      </div>
      <strong>{value}</strong>
      <div className="metric-foot">
        {detail ? <span>{detail}</span> : null}
        {trend ? <Badge state={state} label={trend} /> : null}
      </div>
    </article>
  );
}

export function FilterBar({
  filters,
}: {
  readonly filters: readonly { readonly label: string; readonly value: string; readonly state?: HelmSemanticState }[];
}) {
  return (
    <div className="filter-bar" aria-label="Active filters">
      <Filter size={14} aria-hidden="true" />
      {filters.map((filter) => (
        <button key={`${filter.label}-${filter.value}`} type="button" className="filter-chip" aria-label={`Filter ${filter.label}: ${filter.value}`}>
          <span>{filter.label}</span>
          {filter.state ? <span className={`filter-dot rail-bg--${railForState(filter.state)}`} aria-hidden="true" /> : null}
          <strong>{filter.value}</strong>
        </button>
      ))}
      <button type="button" className="icon-button" aria-label="Open advanced filters">
        <SlidersHorizontal size={14} aria-hidden="true" />
      </button>
    </div>
  );
}

export function SegmentedControl<TValue extends string>({
  value,
  options,
  onChange,
  label,
}: {
  readonly value: TValue;
  readonly options: readonly { readonly value: TValue; readonly label: string }[];
  readonly onChange: (value: TValue) => void;
  readonly label: string;
}) {
  return (
    <div className="segmented-control" role="radiogroup" aria-label={label}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          role="radio"
          aria-checked={option.value === value}
          className={option.value === value ? "is-active" : ""}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function Stepper({
  steps,
}: {
  readonly steps: readonly { readonly label: string; readonly detail: string; readonly state: HelmSemanticState }[];
}) {
  return (
    <ol className="stepper" aria-label="Process steps">
      {steps.map((step, index) => (
        <li key={step.label} className={`rail-border--${railForState(step.state)}`}>
          <span className="step-index">{String(index + 1).padStart(2, "0")}</span>
          <div>
            <strong>{step.label}</strong>
            <span>{step.detail}</span>
          </div>
          <Badge state={step.state} label={labelForState(step.state)} dot />
        </li>
      ))}
    </ol>
  );
}

export function ProgressRail({
  label,
  value,
  state = "verified",
}: {
  readonly label: string;
  readonly value: number;
  readonly state?: HelmSemanticState;
}) {
  const rail = railForState(state);
  return (
    <div className="progress-rail" aria-label={`${label}: ${value}%`}>
      <div className="progress-meta">
        <span>{label}</span>
        <strong>{value}%</strong>
      </div>
      <div className="progress-track">
        <span className={`progress-fill rail-bg--${rail}`} style={{ width: `${value}%` }} />
      </div>
    </div>
  );
}

export function SkeletonRows({ count = 4 }: { readonly count?: number }) {
  return (
    <div className="skeleton-stack" role="status" aria-label="Loading rows">
      {Array.from({ length: count }, (_, index) => (
        <div key={index} className="skeleton-row">
          <span />
          <span />
          <span />
        </div>
      ))}
    </div>
  );
}

export function Pagination({
  page,
  pages,
}: {
  readonly page: number;
  readonly pages: number;
}) {
  return (
    <nav className="pagination" aria-label="Pagination">
      <button type="button" className="icon-button" aria-label="Previous page" disabled={page <= 1}>
        <ChevronLeft size={14} aria-hidden="true" />
      </button>
      <span>
        Page <strong>{page}</strong> of <strong>{pages}</strong>
      </span>
      <button type="button" className="icon-button" aria-label="Next page" disabled={page >= pages}>
        <ChevronRight size={14} aria-hidden="true" />
      </button>
    </nav>
  );
}

export type ToastTone = "verified" | "escalate" | "live" | "deny" | "pending" | "failed";

export interface ToastInput {
  readonly title: string;
  readonly detail?: string;
  readonly tone?: ToastTone;
  readonly duration?: number;
  readonly action?: { readonly label: string; readonly onClick: () => void };
}

interface ToastEntry extends ToastInput {
  readonly id: string;
  readonly tone: ToastTone;
}

interface ToastContextValue {
  readonly toasts: readonly ToastEntry[];
  readonly push: (input: ToastInput) => string;
  readonly dismiss: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: { readonly children: ReactNode }) {
  const [toasts, setToasts] = useState<readonly ToastEntry[]>([]);
  const timersRef = useRef<Map<string, number>>(new Map());
  const seedRef = useRef(0);

  const dismiss = useCallback((id: string) => {
    const handle = timersRef.current.get(id);
    if (handle !== undefined) {
      window.clearTimeout(handle);
      timersRef.current.delete(id);
    }
    setToasts((items) => items.filter((toast) => toast.id !== id));
  }, []);

  const push = useCallback((input: ToastInput) => {
    seedRef.current += 1;
    const id = `toast-${seedRef.current}`;
    const tone: ToastTone = input.tone ?? "verified";
    const duration = input.duration ?? 4500;
    setToasts((items) => [...items, { ...input, id, tone }]);
    if (duration > 0 && Number.isFinite(duration)) {
      const handle = window.setTimeout(() => dismiss(id), duration);
      timersRef.current.set(id, handle);
    }
    return id;
  }, [dismiss]);

  useEffect(() => {
    const timers = timersRef.current;
    return () => {
      for (const handle of timers.values()) window.clearTimeout(handle);
      timers.clear();
    };
  }, []);

  const value = useMemo(() => ({ toasts, push, dismiss }), [toasts, push, dismiss]);
  return <ToastContext.Provider value={value}>{children}</ToastContext.Provider>;
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used inside <ToastProvider>");
  return { push: ctx.push, dismiss: ctx.dismiss };
}

export function useOptionalToast() {
  const ctx = useContext(ToastContext);
  return useMemo(
    () => ({
      push: ctx?.push ?? (() => ""),
      dismiss: ctx?.dismiss ?? (() => undefined),
    }),
    [ctx],
  );
}

const TOAST_ICON: Record<ToastTone, ComponentType<{ size?: number; "aria-hidden"?: boolean }>> = {
  verified: CheckCircle2,
  escalate: Bell,
  live: Activity,
  deny: X,
  pending: Loader2,
  failed: AlertTriangle,
};

export function Toaster() {
  const ctx = useContext(ToastContext);
  if (!ctx) return null;
  return (
    <div className="toast-viewport" role="region" aria-live="polite" aria-label="Notifications">
      {ctx.toasts.map((toast) => {
        const Icon = TOAST_ICON[toast.tone];
        return (
          <article key={toast.id} className={`toast rail-border--${toast.tone}`}>
            <Icon size={14} aria-hidden={true} />
            <div className="toast-body">
              <strong>{toast.title}</strong>
              {toast.detail ? <span>{toast.detail}</span> : null}
            </div>
            <div className="toast-controls">
              {toast.action ? (
                <button
                  type="button"
                  className="toast-action"
                  onClick={() => {
                    toast.action?.onClick();
                    ctx.dismiss(toast.id);
                  }}
                >
                  {toast.action.label}
                </button>
              ) : null}
              <button type="button" className="icon-button" aria-label="Dismiss notification" onClick={() => ctx.dismiss(toast.id)}>
                <X size={13} aria-hidden="true" />
              </button>
            </div>
          </article>
        );
      })}
    </div>
  );
}

export function ToastStack() {
  return (
    <div className="toast-stack" aria-label="Notification examples">
      <article className="toast rail-border--verified">
        <CheckCircle2 size={14} aria-hidden="true" />
        <div><strong>Receipt verified</strong><span>ep_9f82c31a · manifest hash matched</span></div>
      </article>
      <article className="toast rail-border--escalate">
        <Bell size={14} aria-hidden="true" />
        <div><strong>Second reviewer required</strong><span>release.high_risk.v2 · production</span></div>
      </article>
      <article className="toast rail-border--live">
        <Activity size={14} aria-hidden="true" />
        <div><strong>Live feed streaming</strong><span>6 decisions in the last minute</span></div>
      </article>
    </div>
  );
}

export function CommandBar() {
  return (
    <div className="command-bar" aria-label="Object command bar">
      <Button variant="proof" size="sm" leading={<ShieldCheck size={13} aria-hidden="true" />}>Verify</Button>
      <Button variant="secondary" size="sm" leading={<RefreshCw size={13} aria-hidden="true" />}>Replay</Button>
      <Button variant="terminal" size="sm" leading={<Terminal size={13} aria-hidden="true" />}>CLI</Button>
      <button type="button" className="icon-button" aria-label="More object actions">
        <MoreHorizontal size={14} aria-hidden="true" />
      </button>
    </div>
  );
}

export function KeyValueList({
  items,
}: {
  readonly items: readonly { readonly label: string; readonly value: ReactNode }[];
}) {
  return (
    <dl className="key-value-list">
      {items.map((item) => (
        <div key={item.label}>
          <dt>{item.label}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function TimelineScrubber() {
  return (
    <div className="timeline-scrubber">
      <CalendarClock size={14} aria-hidden="true" />
      <div className="timeline-track" aria-hidden="true">
        <span className="timeline-range" />
        <span className="timeline-thumb" />
      </div>
      <span>19:15:50.089Z</span>
    </div>
  );
}

export function ChecklistPanel({
  items,
  state = "verified",
}: {
  readonly items: readonly string[];
  readonly state?: HelmSemanticState;
}) {
  return (
    <div className="checklist-panel">
      {items.map((item) => (
        <div key={item} className={`checklist-row rail-border--${railForState(state)}`}>
          <ListChecks size={14} aria-hidden="true" />
          <span>{item}</span>
        </div>
      ))}
    </div>
  );
}

export interface ActionRecord {
  readonly id: string;
  readonly timestamp: string;
  readonly agent: string;
  readonly action: string;
  readonly target: string;
  readonly environment: EnvironmentState;
  readonly risk: RiskState;
  readonly policy: string;
  readonly verdict: VerdictState;
  readonly receipt: string;
  readonly verification: VerificationState;
}

export interface ActionRecordProps {
  readonly record: ActionRecord;
  readonly density?: Density;
  readonly mode?: Mode;
  readonly selected?: boolean;
  readonly permission?: PermissionState;
  readonly onInspect?: (record: ActionRecord) => void;
}

export function ActionRecordRow({ record, density = "compact", mode = "shared", selected = false, permission = "allowed", onInspect }: ActionRecordProps) {
  const rail = selected ? "selected" : VERDICT_SEMANTICS[record.verdict].rail;
  return (
    <tr className={`action-row rail-border--${rail} density--${density} mode--${mode}`} data-selected={selected || undefined} data-permission={permission}>
      <td data-label="Timestamp"><code>{record.timestamp}</code></td>
      <td data-label="Agent">{record.agent}</td>
      <td data-label="Action">{record.action}</td>
      <td data-label="Target">{record.target}</td>
      <td data-label="Environment"><EnvironmentBadge env={record.environment} /></td>
      <td data-label="Risk"><RiskBadge risk={record.risk} /></td>
      <td data-label="Policy"><code>{record.policy}</code></td>
      <td data-label="Verdict"><VerdictBadge state={record.verdict} intensity={selected ? "active" : "historical"} /></td>
      <td data-label="Receipt"><HashText value={record.receipt} kind="receipt" truncate /></td>
      <td data-label="Verification"><VerificationStatus state={record.verification} /></td>
      <td data-label="Actions">
        <Button variant="ghost" size="sm" onClick={() => onInspect?.(record)}>
          Inspect
        </Button>
      </td>
    </tr>
  );
}

const ACTION_TABLE_INITIAL_WINDOW = 100;
const ACTION_TABLE_INCREMENT = 100;

export function ActionRecordTable({
  records,
  selectedId,
  onInspect,
}: {
  readonly records: readonly ActionRecord[];
  readonly selectedId?: string;
  readonly onInspect?: (record: ActionRecord) => void;
}) {
  const total = records.length;
  const [windowSize, setWindowSize] = useState(ACTION_TABLE_INITIAL_WINDOW);
  const sentinelRef = useRef<HTMLTableCellElement | null>(null);
  const visibleWindowSize = Math.min(windowSize, total);

  useEffect(() => {
    if (visibleWindowSize >= total) return undefined;
    const sentinel = sentinelRef.current;
    if (!sentinel || typeof IntersectionObserver === "undefined") return undefined;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setWindowSize((current) => Math.min(total, current + ACTION_TABLE_INCREMENT));
        }
      },
      { rootMargin: "240px" },
    );
    observer.observe(sentinel);
    return () => observer.disconnect();
  }, [total, visibleWindowSize]);

  const slice = useMemo(() => records.slice(0, visibleWindowSize), [records, visibleWindowSize]);
  const remaining = total - visibleWindowSize;

  return (
    <div className="table-frame" tabIndex={0} aria-label="Scrollable action records table">
      <table className="data-table action-table">
        <caption className="sr-only">Action records in canonical timestamp, agent, action, target, environment, risk, policy, verdict, receipt, verification, actions order.</caption>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Agent</th>
            <th>Action</th>
            <th>Target</th>
            <th>Environment</th>
            <th>Risk</th>
            <th>Policy</th>
            <th>Verdict</th>
            <th>Receipt</th>
            <th>Verification</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {slice.map((record) => (
            <ActionRecordRow key={record.id} record={record} selected={record.id === selectedId} onInspect={onInspect} />
          ))}
          {remaining > 0 ? (
            <tr className="action-table-sentinel">
              <td ref={sentinelRef} colSpan={11} aria-live="polite">
                <span>
                  Showing {windowSize.toLocaleString()} of {total.toLocaleString()} records.
                </span>
                <button type="button" className="link-button" onClick={() => setWindowSize(total)}>
                  Show all
                </button>
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}

export interface CommandPaletteItem {
  readonly id: string;
  readonly kind: "ask" | "nav" | "action" | "policy" | "receipt" | "agent";
  readonly label: string;
  readonly shortcut?: string;
}

export function CommandPalette({
  open,
  items,
  onClose,
  onSelect,
}: {
  readonly open: boolean;
  readonly items: readonly CommandPaletteItem[];
  readonly onClose: () => void;
  readonly onSelect: (item: CommandPaletteItem) => void;
}) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return items;
    return items.filter((item) => item.label.toLowerCase().includes(needle) || item.kind.includes(needle));
  }, [items, query]);
  useDialogFocusTrap(open, dialogRef, onClose);
  useEffect(() => {
    if (!open) return;
    window.requestAnimationFrame(() => inputRef.current?.focus());
  }, [open]);
  if (!open) return null;
  const activeItem = filtered[active];
  return (
    <div className="palette-backdrop" role="presentation" onMouseDown={onClose}>
      <div
        ref={dialogRef}
        className="command-palette"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        tabIndex={-1}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <label className="palette-search">
          <Search size={15} aria-hidden="true" />
          <input
            ref={inputRef}
            value={query}
            placeholder="Ask HELM or search receipts, policies, agents..."
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-results"
            aria-activedescendant={activeItem ? `palette-${activeItem.id}` : undefined}
            onChange={(event) => {
              setQuery(event.target.value);
              setActive(0);
            }}
            onKeyDown={(event) => {
              if (event.key === "ArrowDown") {
                event.preventDefault();
                setActive((index) => Math.min(filtered.length - 1, index + 1));
              }
              if (event.key === "ArrowUp") {
                event.preventDefault();
                setActive((index) => Math.max(0, index - 1));
              }
              if (event.key === "Enter" && activeItem) {
                onSelect(activeItem);
                onClose();
              }
            }}
          />
        </label>
        <div id="palette-results" className="palette-results" role="listbox" aria-label="Command results">
          {filtered.length === 0 ? <div className="palette-empty">No matching command or source.</div> : null}
          {filtered.map((item, index) => (
            <button
              id={`palette-${item.id}`}
              key={item.id}
              type="button"
              role="option"
              aria-selected={index === active}
              className={`palette-result ${index === active ? "is-active" : ""}`}
              onMouseEnter={() => setActive(index)}
              onClick={() => {
                onSelect(item);
                onClose();
              }}
            >
              <span className="palette-kind">{item.kind}</span>
              <span>{item.label}</span>
              {item.shortcut ? <kbd>{item.shortcut}</kbd> : null}
            </button>
          ))}
        </div>
        <footer className="palette-footer">Arrow keys navigate. Enter opens. Escape closes. Assistant answers must cite HELM sources.</footer>
      </div>
    </div>
  );
}

export function ShellIcon({ name }: { readonly name: "shield" | "terminal" | "receipt" | "policy" | "evidence" | "approval" | "lock" | "json" | "chevron" | "warning" }) {
  const size = 15;
  switch (name) {
    case "shield": return <ShieldCheck size={size} aria-hidden="true" />;
    case "terminal": return <Terminal size={size} aria-hidden="true" />;
    case "receipt": return <Clipboard size={size} aria-hidden="true" />;
    case "policy": return <KeyRound size={size} aria-hidden="true" />;
    case "evidence": return <Archive size={size} aria-hidden="true" />;
    case "approval": return <CheckCircle2 size={size} aria-hidden="true" />;
    case "lock": return <Lock size={size} aria-hidden="true" />;
    case "json": return <FileJson size={size} aria-hidden="true" />;
    case "chevron": return <ChevronDown size={size} aria-hidden="true" />;
    case "warning": return <AlertTriangle size={size} aria-hidden="true" />;
  }
}
