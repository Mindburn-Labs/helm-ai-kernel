import { Columns3, Download, Filter, Search, View } from "lucide-react";
import { type ReactNode } from "react";
import { Button } from "./core";
import { StatusPill } from "./status";
import { type HelmSemanticState } from "../state/semantics";

export function FilterChip({ label, value, state = "historical" }: { readonly label: string; readonly value: string; readonly state?: HelmSemanticState }) {
  return (
    <button type="button" className="filter-chip-v2" aria-label={`${label}: ${value}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <StatusPill state={state} label="" ariaLabel={`${state} filter state`} />
    </button>
  );
}

export function SavedViewTabs({
  views,
  active,
  onChange,
}: {
  readonly views: readonly string[];
  readonly active: string;
  readonly onChange: (view: string) => void;
}) {
  return (
    <div className="saved-view-tabs" role="tablist" aria-label="Saved data views">
      {views.map((view) => (
        <button key={view} type="button" role="tab" aria-selected={active === view} className={active === view ? "is-active" : ""} onClick={() => onChange(view)}>
          {view}
        </button>
      ))}
    </div>
  );
}

export function DataToolbar({
  title,
  activeView,
  onViewChange,
  children,
}: {
  readonly title: string;
  readonly activeView: string;
  readonly onViewChange: (view: string) => void;
  readonly children?: ReactNode;
}) {
  return (
    <div className="data-toolbar">
      <div className="data-toolbar-title">
        <span>{title}</span>
        <SavedViewTabs views={["Live", "Denied", "Production", "Retained"]} active={activeView} onChange={onViewChange} />
      </div>
      <label className="data-toolbar-search">
        <Search size={14} aria-hidden="true" />
        <span className="sr-only">Search records</span>
        <input placeholder="Search receipts, agents, policies..." />
      </label>
      <div className="data-toolbar-actions">
        {children}
        <Button variant="ghost" size="sm" leading={<Filter size={13} aria-hidden="true" />}>Filter</Button>
        <Button variant="ghost" size="sm" leading={<Columns3 size={13} aria-hidden="true" />}>Columns</Button>
        <Button variant="proof" size="sm" leading={<Download size={13} aria-hidden="true" />}>Export</Button>
      </div>
    </div>
  );
}

export function BulkActionBar({ selectedCount }: { readonly selectedCount: number }) {
  return (
    <div className="bulk-action-bar">
      <div>
        <View size={14} aria-hidden="true" />
        <strong>{selectedCount}</strong>
        <span>records selected</span>
      </div>
      <Button variant="secondary" size="sm">Assign reviewer</Button>
      <Button variant="proof" size="sm">Verify selected</Button>
      <Button variant="danger" size="sm">Clear selection</Button>
    </div>
  );
}
