import { useEffect, useState, type ReactNode } from 'react';
import { Link, NavLink } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  Clock3,
  ExternalLink,
  History,
  Loader2,
  Play,
  Shield,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import type { ArtifactRef, InspectorTab, OperatorAction, StateSignal, TruthStamp } from '../types/operator';
import type { RiskLevel, Surface } from '../types/domain';
import { formatDateTime, formatRelativeTime, getSurfaceLabel } from './model';

export function SurfaceNavigation({
  workspaceId,
  activeSurface,
  approvalCount,
}: {
  workspaceId: string;
  activeSurface: Surface;
  approvalCount: number;
}) {
  const surfaces: Surface[] = ['canvas', 'operate', 'research', 'govern', 'proof', 'chat'];

  return (
    <nav aria-label="Workspace surfaces" className="operator-surface-nav">
      {surfaces.map((surface) => (
        <NavLink
          key={surface}
          className={({ isActive }) =>
            `operator-surface-link${isActive || activeSurface === surface ? ' is-active' : ''}`
          }
          to={`/workspaces/${workspaceId}/${surface}`}
        >
          <span>{getSurfaceLabel(surface)}</span>
          {surface === 'operate' && approvalCount > 0 ? (
            <span className="operator-count-pill">{approvalCount}</span>
          ) : null}
        </NavLink>
      ))}
    </nav>
  );
}

export function TopStatusPill({
  label,
  value,
  tone = 'neutral',
}: {
  label: string;
  value: string;
  tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'info';
}) {
  return (
    <div className={`operator-meta-pill tone-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function SignalStrip({ signals }: { signals: StateSignal[] }) {
  return (
    <section className="operator-signal-strip" aria-label="Operator control strip">
      {signals.map((signal) => (
        <article key={signal.key} className={`operator-signal-card tone-${signal.tone}`}>
          <div className="operator-signal-head">
            <span>{signal.label}</span>
            <SignalToneIcon tone={signal.tone} />
          </div>
          <strong>{signal.value}</strong>
          <p>{signal.detail}</p>
        </article>
      ))}
    </section>
  );
}

export function Panel({
  title,
  description,
  actions,
  children,
  className = '',
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`operator-panel ${className}`.trim()}>
      <header className="operator-panel-header">
        <div>
          <h2>{title}</h2>
          {description ? <p>{description}</p> : null}
        </div>
        {actions ? <div className="operator-panel-actions">{actions}</div> : null}
      </header>
      {children}
    </section>
  );
}

export function SurfaceIntro({
  eyebrow,
  title,
  description,
  actions,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <section className="operator-surface-intro">
      <div>
        <span className="operator-eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions ? <div className="operator-surface-actions">{actions}</div> : null}
      {children}
    </section>
  );
}

export function TruthBadge({ truth }: { truth: TruthStamp }) {
  return (
    <div className={`operator-truth-badge stage-${truth.stage}`}>
      <TruthStageIcon stage={truth.stage} />
      <div>
        <strong>{truth.label}</strong>
        <span>{truth.detail}</span>
      </div>
    </div>
  );
}

export function ArtifactList({
  workspaceId,
  artifacts,
}: {
  workspaceId: string;
  artifacts: ArtifactRef[];
}) {
  if (artifacts.length === 0) {
    return <EmptyState title="No linked artifacts" body="This surface has not produced canonical objects yet." compact />;
  }

  return (
    <ul className="operator-artifact-list">
      {artifacts.map((artifact) => (
        <li key={artifact.id} className="operator-artifact-item">
          <div>
            <span className="operator-artifact-type">{artifact.type}</span>
            <strong>{artifact.title}</strong>
            <p>{artifact.detail}</p>
            {artifact.truth ? <TruthBadge truth={artifact.truth} /> : null}
          </div>
          {artifact.href ? (
            <Link to={artifact.href} className="operator-inline-link">
              Open
              <ChevronRight size={14} />
            </Link>
          ) : (
            <span className="operator-inline-link is-muted">{workspaceId}</span>
          )}
        </li>
      ))}
    </ul>
  );
}

export function ActivityFeed({ items }: { items: Array<{ id: string; title: string; detail: string; timestamp?: string; tone: string }> }) {
  if (items.length === 0) {
    return <p className="operator-empty-inline">No recent activity.</p>;
  }

  return (
    <ol className="operator-activity-list">
      {items.map((item) => (
        <li key={item.id} className={`operator-activity-item tone-${item.tone}`}>
          <div className="operator-activity-marker" />
          <div>
            <strong>{item.title}</strong>
            <p>{item.detail}</p>
            {item.timestamp ? (
              <time dateTime={item.timestamp}>
                {formatRelativeTime(item.timestamp)} · {formatDateTime(item.timestamp)}
              </time>
            ) : null}
          </div>
        </li>
      ))}
    </ol>
  );
}

export function Inspector({
  title,
  subtitle,
  tabs,
}: {
  title: string;
  subtitle?: string;
  tabs: InspectorTab[];
}) {
  const [activeTab, setActiveTab] = useState<InspectorTab['id'] | null>(null);
  const resolvedActiveTab = tabs.some((tab) => tab.id === activeTab) ? activeTab : (tabs[0]?.id ?? 'overview');
  const activeContent = tabs.find((tab) => tab.id === resolvedActiveTab)?.content;

  return (
    <aside className="operator-inspector" aria-label="Shared inspector">
      <header className="operator-inspector-header">
        <span className="operator-eyebrow">Inspector</span>
        <h2>{title}</h2>
        {subtitle ? <p>{subtitle}</p> : null}
      </header>
      <div className="operator-tab-strip" role="tablist" aria-label="Inspector tabs">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            className={`operator-tab${tab.id === resolvedActiveTab ? ' is-active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
            role="tab"
            aria-selected={tab.id === resolvedActiveTab}
            type="button"
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div className="operator-inspector-body">{activeContent}</div>
    </aside>
  );
}

export function EmptyState({
  title,
  body,
  action,
  compact = false,
}: {
  title: string;
  body: string;
  action?: ReactNode;
  compact?: boolean;
}) {
  return (
    <div className={`operator-empty-state${compact ? ' compact' : ''}`}>
      <Shield size={compact ? 18 : 28} />
      <div>
        <strong>{title}</strong>
        <p>{body}</p>
      </div>
      {action ? <div>{action}</div> : null}
    </div>
  );
}

export function LoadingState({ label = 'Loading live operator data…' }: { label?: string }) {
  return (
    <div className="operator-loading-state">
      <Loader2 className="operator-spinner" size={18} />
      <span>{label}</span>
    </div>
  );
}

export function ErrorState({
  title,
  error,
  retry,
}: {
  title: string;
  error: unknown;
  retry?: () => void;
}) {
  const description = error instanceof Error ? error.message : 'The live service did not return a usable response.';

  return (
    <div className="operator-error-state" role="alert">
      <AlertTriangle size={18} />
      <div>
        <strong>{title}</strong>
        <p>{description}</p>
      </div>
      {retry ? (
        <button className="operator-button secondary" onClick={retry} type="button">
          Retry
        </button>
      ) : null}
    </div>
  );
}

export function ActionButton({
  action,
  onClick,
  disabled,
}: {
  action: OperatorAction;
  onClick?: () => void;
  disabled?: boolean;
}) {
  const content = (
    <>
      <span>{action.title}</span>
      {action.href ? <ArrowRight size={14} /> : null}
    </>
  );

  if (action.href) {
    return (
      <Link
        to={action.href}
        className={`operator-button ${action.emphasis}`}
        aria-label={`${action.title}: ${action.detail}`}
      >
        {content}
      </Link>
    );
  }

  return (
    <button
      className={`operator-button ${action.emphasis}`}
      disabled={disabled}
      onClick={onClick}
      type="button"
      title={action.detail}
    >
      {content}
    </button>
  );
}

export function ConfirmActionButton({
  label,
  confirmLabel,
  description,
  onConfirm,
  disabled,
  tone = 'danger',
}: {
  label: string;
  confirmLabel: string;
  description: string;
  onConfirm: () => void | Promise<void>;
  disabled?: boolean;
  tone?: 'danger' | 'warning';
}) {
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    if (!armed) {
      return undefined;
    }

    const timeoutId = window.setTimeout(() => setArmed(false), 4_000);
    return () => window.clearTimeout(timeoutId);
  }, [armed]);

  if (!armed) {
    return (
      <button
        className={`operator-button ${tone === 'danger' ? 'danger' : 'secondary'}`}
        disabled={disabled}
        onClick={() => setArmed(true)}
        type="button"
      >
        {label}
      </button>
    );
  }

  return (
    <div className={`operator-confirm-card tone-${tone}`}>
      <p>{description}</p>
      <div className="operator-confirm-actions">
        <button
          className={`operator-button ${tone === 'danger' ? 'danger' : 'primary'}`}
          onClick={() => {
            void Promise.resolve(onConfirm()).finally(() => setArmed(false));
          }}
          type="button"
        >
          {confirmLabel}
        </button>
        <button className="operator-button ghost" onClick={() => setArmed(false)} type="button">
          Cancel
        </button>
      </div>
    </div>
  );
}

export function JsonPreview({ data, label = 'Structured detail' }: { data: unknown; label?: string }) {
  return (
    <div className="operator-json-preview">
      <span className="operator-eyebrow">{label}</span>
      <pre>{JSON.stringify(data, null, 2)}</pre>
    </div>
  );
}

export function DetailList({
  items,
}: {
  items: Array<{ label: string; value: string | ReactNode }>;
}) {
  return (
    <dl className="operator-detail-list">
      {items.map((item) => (
        <div key={item.label}>
          <dt>{item.label}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function QueueTable({
  rows,
  columns,
}: {
  rows: Array<Record<string, ReactNode>>;
  columns: Array<{ key: string; label: string }>;
}) {
  if (rows.length === 0) {
    return <p className="operator-empty-inline">Nothing to show.</p>;
  }

  return (
    <div className="operator-table-shell">
      <table className="operator-table">
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key}>{column.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={String(row.id ?? index)}>
              {columns.map((column) => (
                <td key={column.key}>{row[column.key]}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function TruthStageIcon({ stage }: { stage: TruthStamp['stage'] }) {
  switch (stage) {
    case 'active':
    case 'approved':
    case 'verified':
      return <ShieldCheck size={16} />;
    case 'blocked':
      return <ShieldAlert size={16} />;
    case 'running':
      return <Play size={16} />;
    case 'completed':
      return <CheckCircle2 size={16} />;
    case 'draft':
    case 'proposed':
      return <Clock3 size={16} />;
    default:
      return <History size={16} />;
  }
}

export function RiskPill({ risk }: { risk: RiskLevel }) {
  return <span className={`operator-risk-pill risk-${risk}`}>{risk.toUpperCase()}</span>;
}

export function ExternalTextLink({ href, label }: { href: string; label: string }) {
  return (
    <a className="operator-inline-link" href={href} rel="noreferrer" target="_blank">
      {label}
      <ExternalLink size={14} />
    </a>
  );
}

function SignalToneIcon({ tone }: { tone: StateSignal['tone'] }) {
  switch (tone) {
    case 'success':
      return <CheckCircle2 size={14} />;
    case 'warning':
      return <AlertTriangle size={14} />;
    case 'danger':
      return <XCircle size={14} />;
    case 'info':
      return <ShieldCheck size={14} />;
    default:
      return <Clock3 size={14} />;
  }
}
