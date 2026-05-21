import type { ComponentType, ReactNode, RefObject } from "react";
import { Search, X } from "lucide-react";
import { Button, type ButtonVariant } from "./core";
import { FormField, TextInput, TextareaField } from "./forms";
import type { RailState } from "../state/semantics";

export interface WorkbenchShellProps {
  readonly rail: ReactNode;
  readonly header: ReactNode;
  readonly children: ReactNode;
  readonly drawer?: ReactNode;
  readonly mobileNav?: ReactNode;
  readonly securityStance?: "allow" | "deny" | "escalate" | "pending";
}

export function WorkbenchShell({ rail, header, children, drawer, mobileNav, securityStance = "pending" }: WorkbenchShellProps) {
  return (
    <div className={`cockpit-shell stance-${securityStance}`} data-security-stance={securityStance}>
      {rail}
      <main className="cockpit-main">
        {header}
        <div className="cockpit-content">
          <section className="cockpit-workspace" aria-label="HELM governed agent workspace">
            {children}
          </section>
          {drawer}
        </div>
      </main>
      {mobileNav}
    </div>
  );
}

export interface WorkbenchRailProps {
  readonly brand: string;
  readonly mark?: string;
  readonly children: ReactNode;
  readonly onBrandClick?: () => void;
}

export function WorkbenchRail({ brand, mark = brand.slice(0, 1), children, onBrandClick }: WorkbenchRailProps) {
  return (
    <aside className="cockpit-rail" aria-label="HELM navigation">
      <button type="button" className="rail-brand" onClick={onBrandClick}>
        <span className="brand-sigil" aria-hidden="true">{mark}</span>
        <span>{brand}</span>
      </button>
      <nav className="rail-nav" aria-label="Primary flows">
        {children}
      </nav>
    </aside>
  );
}

export interface WorkbenchRailLinkProps {
  readonly active?: boolean;
  readonly label: string;
  readonly count?: number;
  readonly icon?: ComponentType<{ readonly size?: number; readonly "aria-hidden"?: boolean }>;
  readonly onClick: () => void;
}

export function WorkbenchRailLink({ active = false, label, count, icon: Icon, onClick }: WorkbenchRailLinkProps) {
  return (
    <button
      type="button"
      className={active ? "rail-link is-active" : "rail-link"}
      aria-label={label}
      aria-current={active ? "page" : undefined}
      onClick={onClick}
    >
      {Icon ? <Icon size={17} aria-hidden /> : <span aria-hidden />}
      <span>{label}</span>
      {count ? <em>{count}</em> : null}
    </button>
  );
}

export function WorkbenchMobileNav({ children }: { readonly children: ReactNode }) {
  return <nav className="mobile-nav" aria-label="Primary flows">{children}</nav>;
}

export function WorkbenchMobileNavButton({
  active = false,
  label,
  icon: Icon,
  onClick,
}: Omit<WorkbenchRailLinkProps, "count">) {
  return (
    <button
      type="button"
      className={active ? "mobile-nav-button is-active" : "mobile-nav-button"}
      aria-label={label}
      onClick={onClick}
    >
      {Icon ? <Icon size={18} aria-hidden /> : null}
      <span>{label}</span>
    </button>
  );
}

export interface WorkbenchHeaderProps {
  readonly eyebrow: string;
  readonly title: string;
  readonly command: ReactNode;
  readonly facts?: ReactNode;
}

export function WorkbenchHeader({ eyebrow, title, command, facts }: WorkbenchHeaderProps) {
  return (
    <header className="cockpit-header">
      <div className="header-title">
        <span>{eyebrow}</span>
        <strong>{title}</strong>
      </div>
      {command}
      {facts ? <div className="header-pills" aria-label="Runtime facts">{facts}</div> : null}
    </header>
  );
}

export interface WorkbenchCommandSearchProps {
  readonly value: string;
  readonly placeholder: string;
  readonly results?: ReactNode;
  readonly onChange: (value: string) => void;
  readonly onEnter: () => void;
}

export function WorkbenchCommandSearch({ value, placeholder, results, onChange, onEnter }: WorkbenchCommandSearchProps) {
  return (
    <div className="global-command" role="search">
      <Search size={15} aria-hidden />
      <input
        type="search"
        value={value}
        placeholder={placeholder}
        aria-label="Search or run a HELM command"
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter") onEnter();
        }}
      />
      {results}
    </div>
  );
}

export interface WorkbenchComposerProps {
  readonly title: string;
  readonly body: string;
  readonly principal: string;
  readonly command: string;
  readonly busy?: boolean;
  readonly commandRef?: RefObject<HTMLTextAreaElement | null>;
  readonly error?: ReactNode;
  readonly onPrincipalChange: (value: string) => void;
  readonly onCommandChange: (value: string) => void;
  readonly onSubmit: () => void;
  readonly secondaryAction?: ReactNode;
}

export function WorkbenchComposer({
  title,
  body,
  principal,
  command,
  busy = false,
  commandRef,
  error,
  onPrincipalChange,
  onCommandChange,
  onSubmit,
  secondaryAction,
}: WorkbenchComposerProps) {
  return (
    <section className="composer-stage" aria-labelledby="workbench-title">
      <div className="stage-copy">
        <h1 id="workbench-title">{title}</h1>
        <p>{body}</p>
      </div>
      <form
        className="intent-composer"
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit();
        }}
      >
        <FormField label="Operator">
          <TextInput value={principal} onValueChange={onPrincipalChange} />
        </FormField>
        <FormField label="Command">
          <TextareaField
            ref={commandRef}
            value={command}
            rows={3}
            placeholder="What should HELM govern, verify, or launch?"
            onValueChange={onCommandChange}
          />
        </FormField>
        <div className="composer-actions">
          <Button type="submit" variant="primary" disabled={busy || command.trim() === ""}>
            {busy ? "Evaluating" : "Run"}
          </Button>
          {secondaryAction}
        </div>
        {error}
      </form>
    </section>
  );
}

export function WorkbenchQuickActions({ children }: { readonly children: ReactNode }) {
  return <section className="quick-actions" aria-label="One click actions">{children}</section>;
}

export interface WorkbenchQuickActionProps {
  readonly label: string;
  readonly hint: string;
  readonly onClick: () => void;
}

export function WorkbenchQuickAction({ label, hint, onClick }: WorkbenchQuickActionProps) {
  return (
    <button type="button" onClick={onClick}>
      <span>{label}</span>
      <small>{hint}</small>
    </button>
  );
}

export interface WorkbenchHealthSummaryProps {
  readonly state: "ready" | "degraded" | "unauthorized" | "unavailable" | "loading";
  readonly label: string;
  readonly message: string;
  readonly action?: ReactNode;
}

export function WorkbenchHealthSummary({ state, label, message, action }: WorkbenchHealthSummaryProps) {
  return (
    <div className={`health-summary state-${state}`}>
      <span className="health-dot" aria-hidden="true" />
      <div>
        <strong>{label}</strong>
        <span>{message}</span>
      </div>
      {action}
    </div>
  );
}

export function WorkbenchSectionHeader({ title, meta }: { readonly title: string; readonly meta?: string }) {
  return (
    <div className="section-head">
      <h2>{title}</h2>
      {meta ? <span>{meta}</span> : null}
    </div>
  );
}

export interface WorkbenchTimelineStepProps {
  readonly state: string;
  readonly title: string;
  readonly detail: string;
  readonly trailing?: ReactNode;
  readonly onClick: () => void;
}

export function WorkbenchTimelineStep({ state, title, detail, trailing, onClick }: WorkbenchTimelineStepProps) {
  return (
    <button type="button" className={`timeline-step state-${state}`} onClick={onClick}>
      <span className="timeline-node" aria-hidden="true" />
      <span>
        <strong>{title}</strong>
        <small>{detail}</small>
      </span>
      {trailing}
    </button>
  );
}

export interface WorkbenchIntegrationCardProps {
  readonly group: string;
  readonly title: string;
  readonly detail: string;
  readonly meta: string;
  readonly action: string;
  readonly status: string;
  readonly onClick: () => void;
}

export function WorkbenchIntegrationCard({ group, title, detail, meta, action, status, onClick }: WorkbenchIntegrationCardProps) {
  return (
    <button type="button" className={`integration-card state-${status}`} onClick={onClick}>
      <span>{group}</span>
      <strong>{title}</strong>
      <small>{detail}</small>
      <em>{meta}</em>
      <b>{action}</b>
    </button>
  );
}

export interface WorkbenchRecordRowProps {
  readonly title: string;
  readonly detail: string;
  readonly meta: string;
  readonly onClick: () => void;
}

export function WorkbenchRecordRow({ title, detail, meta, onClick }: WorkbenchRecordRowProps) {
  return (
    <button type="button" className="record-row" onClick={onClick}>
      <strong>{title}</strong>
      <span>{detail}</span>
      <em>{meta}</em>
    </button>
  );
}

export function WorkbenchDrawerFrame({
  open,
  title = "Context",
  children,
  onClose,
}: {
  readonly open?: boolean;
  readonly title?: string;
  readonly children: ReactNode;
  readonly onClose: () => void;
}) {
  return (
    <aside className={open ? "detail-drawer is-open" : "detail-drawer"} aria-label="Selected detail">
      <header>
        <span>{title}</span>
        {open ? (
          <button type="button" className="icon-button" aria-label="Close detail" onClick={onClose}>
            <X size={15} aria-hidden />
          </button>
        ) : null}
      </header>
      {children}
    </aside>
  );
}

export function WorkbenchStatusFact({
  label,
  value,
  tone = "neutral",
}: {
  readonly label: string;
  readonly value: string;
  readonly tone?: "neutral" | "good" | "warn";
}) {
  return (
    <span className={`status-pill tone-${tone}`}>
      <small>{label}</small>
      <strong>{value}</strong>
    </span>
  );
}

export interface WorkbenchStoreHealthItem {
  readonly id: string;
  readonly label: string;
  readonly status: string;
  readonly backend: string;
  readonly source?: string;
  readonly path?: string;
  readonly detail?: string;
}

export function WorkbenchStoreHealthList({ stores }: { readonly stores: readonly WorkbenchStoreHealthItem[] }) {
  return (
    <div className="store-health-list" role="list" aria-label="Runtime stores">
      {stores.map((store) => (
        <div key={store.id} className={`store-health-row state-${store.status}`} role="listitem">
          <span>
            <strong>{store.label}</strong>
            <small>{store.source ?? store.path ?? store.detail ?? "runtime"}</small>
          </span>
          <em>{store.backend}</em>
          <b>{store.status}</b>
        </div>
      ))}
    </div>
  );
}

export interface WorkbenchRouteCoverageItem {
  readonly method: string;
  readonly path: string;
  readonly auth: string;
  readonly contract_status: string;
  readonly group: string;
  readonly ui_coverage: string;
  readonly unsupported_reason?: string;
}

export function WorkbenchRouteCoverageTable({ routes }: { readonly routes: readonly WorkbenchRouteCoverageItem[] }) {
  return (
    <div className="route-coverage-table" role="table" aria-label="Route coverage">
      <div className="route-coverage-row route-coverage-head" role="row">
        <span role="columnheader">Route</span>
        <span role="columnheader">Auth</span>
        <span role="columnheader">Coverage</span>
      </div>
      {routes.map((route) => (
        <div key={`${route.method}-${route.path}`} className={`route-coverage-row state-${route.ui_coverage}`} role="row">
          <span role="cell">
            <strong>{route.method}</strong>
            <small>{route.path}</small>
          </span>
          <span role="cell">{route.auth}</span>
          <span role="cell">
            <b>{route.ui_coverage}</b>
            {route.unsupported_reason ? <small>{route.unsupported_reason}</small> : null}
          </span>
        </div>
      ))}
    </div>
  );
}

export function WorkbenchProofSection({
  title,
  children,
}: {
  readonly title: string;
  readonly children: ReactNode;
}) {
  return (
    <section className="proof-section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

export function WorkbenchActionSheetFrame({
  title,
  method,
  endpoint,
  risk,
  children,
}: {
  readonly title: string;
  readonly method: string;
  readonly endpoint: string;
  readonly risk: string;
  readonly children: ReactNode;
}) {
  return (
    <section className="action-sheet-frame" aria-labelledby="action-sheet-title">
      <header>
        <span>{method}</span>
        <h3 id="action-sheet-title">{title}</h3>
        <small>{endpoint}</small>
      </header>
      <p>{risk}</p>
      {children}
    </section>
  );
}

export interface WorkbenchExplorerRecord {
  readonly id: string;
  readonly label: string;
  readonly state: string;
  readonly detail: string;
}

export function WorkbenchRecordExplorer({
  records,
  onOpen,
}: {
  readonly records: readonly WorkbenchExplorerRecord[];
  readonly onOpen: (id: string) => void;
}) {
  return (
    <div className="record-explorer" role="list" aria-label="Records">
      {records.map((record) => (
        <button key={record.id} type="button" role="listitem" onClick={() => onOpen(record.id)}>
          <strong>{record.label}</strong>
          <span>{record.detail}</span>
          <em>{record.state}</em>
        </button>
      ))}
    </div>
  );
}

export function actionVariant(kind: "primary" | "secondary" | "danger" | "proof" = "secondary"): ButtonVariant {
  if (kind === "primary") return "primary";
  if (kind === "danger") return "danger";
  if (kind === "proof") return "proof";
  return "secondary";
}
