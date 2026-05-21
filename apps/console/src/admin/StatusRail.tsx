import {
  Activity,
  Archive,
  FileArchive,
  FileCheck2,
  GitBranch,
  LockKeyhole,
  ShieldCheck,
} from "lucide-react";
import type { ConsoleBootstrap, Receipt } from "../api/client";

interface StatusRailProps {
  readonly bootstrap: ConsoleBootstrap | null;
  readonly receipt: Receipt | null;
}

interface StatusRow {
  readonly module: string;
  readonly state: string;
  readonly value: string;
  readonly source: string;
  readonly last: string;
  readonly icon: typeof Activity;
}

export function StatusRail({ bootstrap, receipt }: StatusRailProps) {
  const rows: readonly StatusRow[] = [
    {
      module: "Approvals",
      state: bootstrap?.counts.pending_approvals ? "pending" : "clear",
      value: String(bootstrap?.counts.pending_approvals ?? "unknown"),
      source: "approval ceremonies",
      last: receiptRef(receipt),
      icon: FileCheck2,
    },
    {
      module: "MCP",
      state: bootstrap?.mcp.authorization ?? "unknown",
      value: String(bootstrap?.counts.mcp_tools ?? "unknown"),
      source: bootstrap?.mcp.scopes.join(", ") || "registry",
      last: receiptRef(receipt),
      icon: GitBranch,
    },
    {
      module: "Sandbox",
      state: "fail-closed",
      value: "API backed",
      source: "/api/v1/sandbox/grants",
      last: receiptRef(receipt),
      icon: LockKeyhole,
    },
    {
      module: "Evidence",
      state: "available",
      value: "bundle verify",
      source: "/api/v1/evidence/export",
      last: receiptRef(receipt),
      icon: FileArchive,
    },
    {
      module: "Boundary",
      state: bootstrap?.health.store ?? "unknown",
      value: String(bootstrap?.counts.receipts ?? "unknown"),
      source: "/api/v1/boundary/records",
      last: receiptRef(receipt),
      icon: ShieldCheck,
    },
    {
      module: "Conformance",
      state: bootstrap?.conformance.status ?? "unknown",
      value: bootstrap?.conformance.level ?? "unknown",
      source: bootstrap?.conformance.report_id ?? "/api/v1/conformance/reports",
      last: receiptRef(receipt),
      icon: Archive,
    },
  ];

  return (
    <section className="status-rail" aria-labelledby="operational-status-title">
      <div className="status-rail__header">
        <h2 id="operational-status-title">Status</h2>
        <span>{receiptRef(receipt)}</span>
      </div>
      <ul className="signal-list" aria-label="Operational status">
        {rows.map((row) => {
          const Icon = row.icon;
          return (
            <li className="signal-item" key={row.module} title={`${row.source} · ${row.last}`}>
              <Icon size={16} aria-hidden />
              <span>{row.module}</span>
              <strong>{row.state}</strong>
              <small>{row.value}</small>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function receiptRef(receipt: Receipt | null): string {
  if (!receipt) return "no receipt selected";
  return receipt.receipt_id ?? receipt.decision_id ?? receipt.status ?? "receipt selected";
}
