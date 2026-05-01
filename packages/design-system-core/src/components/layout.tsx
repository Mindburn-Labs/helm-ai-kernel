import { type ReactNode } from "react";
import { Drawer, type ButtonProps, Button } from "./core";
import { type RailState } from "../state/semantics";

export function AppShell({ sidebar, topbar, children }: { readonly sidebar: ReactNode; readonly topbar: ReactNode; readonly children: ReactNode }) {
  return (
    <div className="platform-shell">
      <div className="platform-shell-sidebar">{sidebar}</div>
      <div className="platform-shell-main">
        <header className="platform-shell-topbar">{topbar}</header>
        <div className="platform-shell-content">{children}</div>
      </div>
    </div>
  );
}

export function Topbar({ title, actions }: { readonly title: string; readonly actions?: ReactNode }) {
  return (
    <div className="topbar-kit">
      <div>
        <span>Workspace</span>
        <strong>{title}</strong>
      </div>
      {actions ? <div className="topbar-kit-actions">{actions}</div> : null}
    </div>
  );
}

export function SidebarNav({ items, active }: { readonly items: readonly string[]; readonly active: string }) {
  return (
    <nav className="sidebar-nav-kit" aria-label="Platform navigation example">
      {items.map((item) => (
        <button key={item} type="button" className={item === active ? "is-active" : ""}>
          <span aria-hidden="true" />
          {item}
        </button>
      ))}
    </nav>
  );
}

export function SplitPane({ primary, secondary }: { readonly primary: ReactNode; readonly secondary: ReactNode }) {
  return (
    <div className="split-pane">
      <div className="split-pane-primary">{primary}</div>
      <div className="split-pane-secondary">{secondary}</div>
    </div>
  );
}

export function DetailHeader({
  eyebrow,
  title,
  description,
  rail = "verified",
  actions,
}: {
  readonly eyebrow: string;
  readonly title: string;
  readonly description?: string;
  readonly rail?: RailState;
  readonly actions?: ReactNode;
}) {
  return (
    <header className={`detail-header rail-border--${rail}`}>
      <div>
        <span>{eyebrow}</span>
        <h3>{title}</h3>
        {description ? <p>{description}</p> : null}
      </div>
      {actions ? <div className="detail-header-actions">{actions}</div> : null}
    </header>
  );
}

export function InspectorDrawer({ open, title, children, onClose }: { readonly open: boolean; readonly title: string; readonly children: ReactNode; readonly onClose: () => void }) {
  return <Drawer open={open} title={title} onClose={onClose}>{children}</Drawer>;
}

export function PropertyGrid({ items }: { readonly items: readonly { readonly label: string; readonly value: ReactNode }[] }) {
  return (
    <dl className="property-grid">
      {items.map((item) => (
        <div key={item.label}>
          <dt>{item.label}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function CommandGroup({ actions }: { readonly actions: readonly (ButtonProps & { readonly id: string })[] }) {
  return (
    <div className="command-group">
      {actions.map(({ id, ...action }) => <Button key={id} {...action} />)}
    </div>
  );
}
