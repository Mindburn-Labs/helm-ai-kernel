import { AlertTriangle, CheckCircle2, Clock3, GitCommitHorizontal, ShieldCheck } from "lucide-react";
import { type ReactNode } from "react";
import { StatusPill } from "./status";
import { type HelmSemanticState, railForState } from "../state/semantics";

export function Banner({
  state = "verified",
  title,
  children,
}: {
  readonly state?: HelmSemanticState;
  readonly title: string;
  readonly children: ReactNode;
}) {
  const rail = railForState(state);
  const Icon = state === "failed" || state === "deny" ? AlertTriangle : state === "pending" ? Clock3 : ShieldCheck;
  return (
    <div className={`banner banner--${rail} rail-border--${rail}`} role="status">
      <Icon size={16} aria-hidden="true" />
      <div>
        <strong>{title}</strong>
        <p>{children}</p>
      </div>
      <StatusPill state={state} />
    </div>
  );
}

export function SkeletonBlock({ rows = 3 }: { readonly rows?: number }) {
  return (
    <div className="skeleton-block" role="status" aria-label="Loading preview">
      {Array.from({ length: rows }, (_, index) => <span key={index} />)}
    </div>
  );
}

export function Timeline({
  events,
}: {
  readonly events: readonly { readonly label: string; readonly detail: string; readonly state: HelmSemanticState; readonly time: string }[];
}) {
  return (
    <ol className="timeline-kit" aria-label="Timeline">
      {events.map((event) => (
        <li key={`${event.time}-${event.label}`} className={`rail-border--${railForState(event.state)}`}>
          <span>{event.time}</span>
          <div>
            <strong>{event.label}</strong>
            <p>{event.detail}</p>
          </div>
          <StatusPill state={event.state} />
        </li>
      ))}
    </ol>
  );
}

export function AuditTrail() {
  return (
    <div className="audit-trail">
      <div><CheckCircle2 size={14} aria-hidden="true" /><span>receipt signed</span><code>ep_9f82c31a</code></div>
      <div><GitCommitHorizontal size={14} aria-hidden="true" /><span>policy version pinned</span><code>finance.transfer.threshold.v3</code></div>
      <div><ShieldCheck size={14} aria-hidden="true" /><span>audit event emitted</span><code>audit_3941</code></div>
    </div>
  );
}
