import { CheckCircle2, Circle, Loader2, ShieldAlert, XCircle } from "lucide-react";
import { type ReactNode } from "react";
import { type HelmSemanticState, type RailState, labelForState, railForState } from "../state/semantics";

export type ComponentIntent = "neutral" | "proof" | "decision" | "danger" | "terminal";

export interface SharedVisualProps {
  readonly density?: "compact" | "comfortable";
  readonly state?: HelmSemanticState;
  readonly rail?: RailState;
  readonly intent?: ComponentIntent;
  readonly interactive?: boolean;
  readonly ariaLabel?: string;
}

export interface StatusPillProps extends SharedVisualProps {
  readonly label?: string;
  readonly dot?: boolean;
  readonly icon?: ReactNode;
}

export function StatusPill({ state = "historical", label, dot = true, icon, intent = "neutral", ariaLabel }: StatusPillProps) {
  const rail = railForState(state);
  return (
    <span className={`status-pill status-pill--${intent} rail-text--${rail}`} aria-label={ariaLabel ?? `${label ?? labelForState(state)} status`}>
      {icon ?? (dot ? <span className={`status-pill-dot rail-bg--${rail}`} aria-hidden="true" /> : null)}
      <span>{label ?? labelForState(state)}</span>
    </span>
  );
}

export function StatusLabel(props: StatusPillProps) {
  return <StatusPill {...props} />;
}

export interface StatusLineProps extends SharedVisualProps {
  readonly label: string;
  readonly detail?: string;
  readonly meta?: ReactNode;
}

export function StatusLine({ state = "historical", label, detail, meta, density = "compact", intent = "neutral" }: StatusLineProps) {
  const rail = railForState(state);
  return (
    <div className={`status-line status-line--${density} status-line--${intent} rail-border--${rail}`}>
      <StatusPill state={state} intent={intent} />
      <div className="status-line-copy">
        <strong>{label}</strong>
        {detail ? <span>{detail}</span> : null}
      </div>
      {meta ? <div className="status-line-meta">{meta}</div> : null}
    </div>
  );
}

export interface ProcessStepRowProps extends SharedVisualProps {
  readonly title: string;
  readonly detail: string;
  readonly meta?: ReactNode;
  readonly step?: string;
  readonly active?: boolean;
}

export function ProcessStepRow({ state = "pending", title, detail, meta, step, active = false, density = "compact" }: ProcessStepRowProps) {
  const rail = railForState(state);
  const Icon =
    state === "failed" || state === "deny" || state === "permission_limited" || state === "insufficient_context" ? XCircle :
    state === "verified" || state === "complete" || state === "allow" ? CheckCircle2 :
    state === "escalate" || state === "pending_confirmation" ? ShieldAlert :
    active ? Loader2 :
    Circle;
  return (
    <div className={`process-step-row process-step-row--${density} rail-border--${rail}`} data-active={active || undefined}>
      <div className="process-step-icon">
        <Icon size={15} aria-hidden="true" />
      </div>
      {step ? <span className="process-step-index">{step}</span> : null}
      <div className="process-step-copy">
        <strong>{title}</strong>
        <span>{detail}</span>
      </div>
      <div className="process-step-state">
        <StatusPill state={state} label={labelForState(state)} />
        {meta ? <span className="process-step-meta">{meta}</span> : null}
      </div>
    </div>
  );
}
