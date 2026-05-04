"use client";

import {
  Activity,
  AlertCircle,
  Archive,
  Boxes,
  Braces,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Command as CommandIcon,
  Database,
  FileArchive,
  FileCheck2,
  FileKey2,
  Filter,
  GitBranch,
  KeyRound,
  ListChecks,
  LockKeyhole,
  Play,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  UserRound,
  Workflow,
  XCircle,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Badge,
  Button,
  ErrorBoundary,
  HashText,
  I18nProvider,
  StatusPill,
  TelemetryProvider,
  ThemeProvider,
  VerdictBadge,
  VerificationStatus,
  type HelmSemanticState,
  type RiskState,
  type VerdictState,
  type VerificationState,
} from "@helm/design-system-core";
import {
  evaluateIntent,
  loadBootstrap,
  loadConsoleSurface,
  loadEndpoint,
  loadReceipts,
  watchReceipts,
  type ConsoleBootstrap,
  type ConsoleSurfaceState,
  type Receipt,
} from "./api/client";

const NAV_GROUPS = [
  {
    title: "Workspace",
    items: [
      { id: "command", label: "Command", icon: CommandIcon },
      { id: "overview", label: "Overview", icon: Boxes },
      { id: "agents", label: "Agents", icon: UserRound },
      { id: "actions", label: "Actions", icon: Workflow },
      { id: "approvals", label: "Approvals", icon: FileCheck2 },
      { id: "policies", label: "Policies", icon: FileKey2 },
      { id: "connectors", label: "Connectors", icon: GitBranch },
      { id: "receipts", label: "Receipts", icon: Archive },
      { id: "evidence", label: "Evidence", icon: FileArchive },
      { id: "replay", label: "Replay", icon: RotateCcw },
      { id: "audit", label: "Audit", icon: Braces },
    ],
  },
  {
    title: "System",
    items: [
      { id: "developer", label: "Developer", icon: Terminal },
      { id: "settings", label: "Settings", icon: Settings },
    ],
  },
] as const;

const LIFECYCLE = ["Intent", "Policy", "Decision", "Receipt", "Evidence"] as const;

const ENDPOINT_SURFACES: Record<string, string> = {
  connectors: "/mcp/v1/capabilities",
  evidence: "/api/v1/evidence/soc2",
  replay: "/api/v1/replay/timeline",
};

const CONSOLE_SURFACES = new Set(["overview", "agents", "actions", "approvals", "policies", "audit", "developer", "settings"]);

function normalizeVerdict(value: string | undefined): VerdictState {
  switch ((value ?? "").toLowerCase()) {
    case "allow":
    case "allowed":
      return "allow";
    case "deny":
    case "denied":
      return "deny";
    case "escalate":
    case "escalated":
      return "escalate";
    default:
      return "pending";
  }
}

function normalizeRisk(receipt: Receipt | undefined): RiskState {
  const risk = String(receipt?.metadata?.risk ?? receipt?.metadata?.risk_level ?? "").toLowerCase();
  if (risk === "critical" || risk === "high" || risk === "medium" || risk === "low") return risk;
  if (normalizeVerdict(receipt?.status) === "deny") return "high";
  if (normalizeVerdict(receipt?.status) === "escalate") return "medium";
  return "low";
}

function verificationState(receipt: Receipt | null | undefined): VerificationState {
  if (!receipt) return "pending";
  if (receipt.signature || receipt.output_hash || receipt.blob_hash) return "verified";
  return "pending";
}

function shortHash(value: string | undefined): string {
  if (!value) return "not emitted";
  return value.length > 18 ? `${value.slice(0, 10)}...${value.slice(-6)}` : value;
}

function formatTime(value: string | undefined): string {
  if (!value) return "pending";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function receiptAction(receipt: Receipt | undefined): string {
  return String(receipt?.metadata?.action ?? receipt?.effect_id ?? "waiting");
}

function receiptResource(receipt: Receipt | undefined): string {
  return String(receipt?.metadata?.resource ?? receipt?.metadata?.source ?? "no governed action yet");
}

function mergeReceipts(current: readonly Receipt[], next: readonly Receipt[]): readonly Receipt[] {
  const map = new Map<string, Receipt>();
  for (const receipt of current) map.set(receipt.receipt_id ?? `${receipt.decision_id}-${receipt.lamport_clock}`, receipt);
  for (const receipt of next) map.set(receipt.receipt_id ?? `${receipt.decision_id}-${receipt.lamport_clock}`, receipt);
  return [...map.values()].sort((a, b) => (b.lamport_clock ?? 0) - (a.lamport_clock ?? 0)).slice(0, 200);
}

function useConsoleData() {
  const [bootstrap, setBootstrap] = useState<ConsoleBootstrap | null>(null);
  const [receipts, setReceipts] = useState<readonly Receipt[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [streamState, setStreamState] = useState<"connecting" | "live" | "disconnected">("connecting");
  const [refreshing, setRefreshing] = useState(false);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    setError(null);
    try {
      const [boot, receiptRows] = await Promise.all([loadBootstrap(), loadReceipts(100)]);
      setBootstrap(boot);
      setReceipts(mergeReceipts(boot.receipts, receiptRows));
      setStreamState("live");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Console data failed to load");
      setStreamState("disconnected");
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const stop = watchReceipts(
      (receipt) => {
        setStreamState("live");
        setReceipts((current) => mergeReceipts(current, [receipt]));
      },
      (err) => {
        setError(err.message);
        setStreamState("disconnected");
      },
    );
    return stop;
  }, []);

  return { bootstrap, receipts, error, streamState, refreshing, refresh, setReceipts };
}

function useSurfaceState(active: string) {
  const [state, setState] = useState<ConsoleSurfaceState | null>(null);
  const [endpointState, setEndpointState] = useState<{ readonly status: number; readonly ok: boolean; readonly data: unknown } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setState(null);
    setEndpointState(null);
    setError(null);

    if (active === "command" || active === "receipts") return undefined;

    const load = async () => {
      setLoading(true);
      try {
        if (CONSOLE_SURFACES.has(active)) {
          const next = await loadConsoleSurface(active);
          if (!cancelled) setState(next);
          return;
        }
        const endpoint = ENDPOINT_SURFACES[active];
        if (endpoint) {
          const next = await loadEndpoint(endpoint);
          if (!cancelled) setEndpointState(next);
          return;
        }
        if (!cancelled) {
          setError(`No OSS endpoint is registered for ${active}.`);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Surface load failed");
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [active]);

  return { state, endpointState, loading, error };
}

export function App() {
  return (
    <ThemeProvider defaultPreference="dark" defaultDensity="compact">
      <I18nProvider defaultLocale="en-US">
        <TelemetryProvider sink={() => undefined}>
          <ErrorBoundary>
            <ConsoleApp />
          </ErrorBoundary>
        </TelemetryProvider>
      </I18nProvider>
    </ThemeProvider>
  );
}

function ConsoleApp() {
  const { bootstrap, receipts, error, streamState, refreshing, refresh, setReceipts } = useConsoleData();
  const [active, setActive] = useState("command");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [intent, setIntent] = useState("LLM_INFERENCE gpt-4.1-mini");
  const [principal, setPrincipal] = useState("operator@local");
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [replayStatus, setReplayStatus] = useState("not checked");
  const surface = useSurfaceState(active);

  const filteredReceipts = useMemo(() => {
    const term = query.trim().toLowerCase();
    if (!term) return receipts;
    return receipts.filter((receipt) => {
      const haystack = [
        receipt.receipt_id,
        receipt.decision_id,
        receipt.effect_id,
        receipt.status,
        receipt.executor_id,
        receiptAction(receipt),
        receiptResource(receipt),
        receipt.blob_hash,
        receipt.output_hash,
      ].join(" ").toLowerCase();
      return haystack.includes(term);
    });
  }, [query, receipts]);

  const selectedReceipt = useMemo(() => {
    return filteredReceipts.find((receipt) => receipt.receipt_id === selectedId) ?? filteredReceipts[0] ?? null;
  }, [filteredReceipts, selectedId]);

  const submitIntent = async () => {
    setSubmitting(true);
    setActionError(null);
    const [action = "LLM_INFERENCE", ...resourceParts] = intent.trim().split(/\s+/);
    const resource = resourceParts.join(" ") || "unspecified";
    try {
      await evaluateIntent({
        principal,
        action,
        resource,
        context: {
          source: "console.command",
          workspace: bootstrap?.workspace,
          entered_at: new Date().toISOString(),
        },
      });
      const updated = await loadReceipts(100);
      setReceipts((current) => mergeReceipts(current, updated));
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Intent evaluation failed");
    } finally {
      setSubmitting(false);
    }
  };

  const runReplayProbe = async () => {
    setReplayStatus("checking");
    try {
      const response = await fetch("/api/v1/replay/timeline");
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.json() as { status?: string; session_id?: string };
      setReplayStatus(payload.status ?? payload.session_id ?? "timeline ready");
    } catch (err) {
      setReplayStatus(err instanceof Error ? err.message : "replay unavailable");
    }
  };

  return (
    <div className="console-shell">
      <Sidebar active={active} onActiveChange={setActive} counts={bootstrap?.counts} />
      <main className="console-main">
        <Topbar bootstrap={bootstrap} active={active} streamState={streamState} query={query} onQueryChange={setQuery} />
        <section className="console-page" aria-label="HELM Console workspace">
          <div className="page-grid">
            <ConsoleIntro active={active} bootstrap={bootstrap} />
            {active === "command" ? (
              <div className="console-stack">
                <CommandSurface
                  bootstrap={bootstrap}
                  receipt={selectedReceipt}
                  intent={intent}
                  principal={principal}
                  submitting={submitting}
                  actionError={actionError}
                  onIntentChange={setIntent}
                  onPrincipalChange={setPrincipal}
                  onSubmit={submitIntent}
                />
                <ReceiptStream
                  receipts={filteredReceipts}
                  selectedId={selectedReceipt?.receipt_id ?? null}
                  refreshing={refreshing}
                  onRefresh={refresh}
                  onSelect={setSelectedId}
                />
              </div>
            ) : active === "receipts" ? (
              <div className="console-stack">
                <ReceiptStream
                  receipts={filteredReceipts}
                  selectedId={selectedReceipt?.receipt_id ?? null}
                  refreshing={refreshing}
                  onRefresh={refresh}
                  onSelect={setSelectedId}
                />
              </div>
            ) : (
              <SurfaceWorkspace active={active} surface={surface} bootstrap={bootstrap} receipts={filteredReceipts} />
            )}
            <Inspector
              bootstrap={bootstrap}
              receipt={selectedReceipt}
              error={error}
              replayStatus={replayStatus}
              onReplay={runReplayProbe}
            />
          </div>
          <OperationsStrip bootstrap={bootstrap} receipt={selectedReceipt} />
        </section>
      </main>
    </div>
  );
}

function Sidebar({
  active,
  counts,
  onActiveChange,
}: {
  readonly active: string;
  readonly counts?: ConsoleBootstrap["counts"];
  readonly onActiveChange: (id: string) => void;
}) {
  const countById: Record<string, number | undefined> = {
    approvals: counts?.pending_approvals,
    receipts: counts?.receipts,
    evidence: counts?.receipts,
    connectors: counts?.mcp_tools,
  };

  return (
    <aside className="console-sidebar">
      <div className="console-brand">
        <span className="brand-glyph" aria-hidden="true" />
        <strong>HELM</strong>
        <span className="version-chip">v0.4.0</span>
      </div>
      {NAV_GROUPS.map((group) => (
        <nav key={group.title} className="nav-block" aria-label={group.title}>
          <h2>{group.title}</h2>
          {group.items.map((item) => {
            const Icon = item.icon;
            const count = countById[item.id];
            return (
              <button
                key={item.id}
                type="button"
                className={item.id === active ? "console-nav-item is-active" : "console-nav-item"}
                onClick={() => onActiveChange(item.id)}
              >
                <Icon size={14} strokeWidth={1.8} aria-hidden="true" />
                <span>{item.label}</span>
                {typeof count === "number" ? <span className="nav-count">{count}</span> : null}
              </button>
            );
          })}
        </nav>
      ))}
      <div className="operator-card">
        <span className="operator-avatar">OP</span>
        <div>
          <strong>op@helm</strong>
          <span>operator · local</span>
        </div>
      </div>
    </aside>
  );
}

function Topbar({
  bootstrap,
  active,
  streamState,
  query,
  onQueryChange,
}: {
  readonly bootstrap: ConsoleBootstrap | null;
  readonly active: string;
  readonly streamState: string;
  readonly query: string;
  readonly onQueryChange: (value: string) => void;
}) {
  return (
    <header className="console-topbar">
      <div className="breadcrumbs">
        <span>Console</span>
        <span>/</span>
        <strong>{surfaceTitle(active)}</strong>
      </div>
      <button type="button" className="env-button">
        <Database size={13} aria-hidden="true" />
        {bootstrap?.workspace.organization ?? "local"} · {bootstrap?.workspace.environment ?? "pending"}
        <ChevronDown size={13} aria-hidden="true" />
      </button>
      <div className="search-field">
        <Search size={13} aria-hidden="true" />
        <input
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          placeholder="Search receipts, agents, policies..."
          aria-label="Search receipts, agents, policies"
        />
        <kbd>⌘K</kbd>
      </div>
      <div className="health-chips" aria-label="Kernel health">
        <HealthChip label="kernel" state={bootstrap?.health.kernel ?? "loading"} />
        <HealthChip label="policy" state={bootstrap?.health.policy ?? "loading"} />
        <HealthChip label="store" state={bootstrap?.health.store ?? "loading"} />
        <HealthChip label="stream" state={streamState} />
      </div>
      <div className="density-toggle" aria-label="Density">
        <span>density</span>
        <button type="button" className="is-active">Compact</button>
        <button type="button">Comfortable</button>
      </div>
    </header>
  );
}

function HealthChip({ label, state }: { readonly label: string; readonly state: string }) {
  const normalized = state === "ready" || state === "active" || state === "live" ? "verified" : state === "loading" ? "pending" : "failed";
  return (
    <span className={`health-chip health-chip--${normalized}`}>
      <span aria-hidden="true" />
      {label}
    </span>
  );
}

function ConsoleIntro({ active, bootstrap }: { readonly active: string; readonly bootstrap: ConsoleBootstrap | null }) {
  return (
    <header className="console-intro">
      <div className="section-index">01 · {active}</div>
      <h1>Governance command</h1>
      <p>
        Deterministic pre-action control, signed receipts, ProofGraph lineage, replay, evidence packs, and conformance in one shell.
      </p>
      <dl>
        <div>
          <dt>version</dt>
          <dd>{bootstrap?.version.version ?? "loading"}</dd>
        </div>
        <div>
          <dt>mode</dt>
          <dd>{bootstrap?.workspace.mode ?? "self-hosted"}</dd>
        </div>
        <div>
          <dt>conformance</dt>
          <dd>{bootstrap?.conformance.level ?? "unreported"}</dd>
        </div>
      </dl>
    </header>
  );
}

function CommandSurface({
  bootstrap,
  receipt,
  intent,
  principal,
  submitting,
  actionError,
  onIntentChange,
  onPrincipalChange,
  onSubmit,
}: {
  readonly bootstrap: ConsoleBootstrap | null;
  readonly receipt: Receipt | null;
  readonly intent: string;
  readonly principal: string;
  readonly submitting: boolean;
  readonly actionError: string | null;
  readonly onIntentChange: (value: string) => void;
  readonly onPrincipalChange: (value: string) => void;
  readonly onSubmit: () => void;
}) {
  const verdict = normalizeVerdict(receipt?.status);
  return (
    <section className="command-surface" aria-labelledby="command-surface-title">
      <div className="panel-head">
        <div>
          <span className="eyebrow">pre-action lifecycle</span>
          <h2 id="command-surface-title">Intent → Policy → Decision → Receipt → Evidence</h2>
        </div>
        <Badge state={verdict as HelmSemanticState} label={receipt ? `decision ${verdict}` : "waiting"} dot />
      </div>
      <div className="intent-composer">
        <label>
          <span>principal</span>
          <input value={principal} onChange={(event) => onPrincipalChange(event.target.value)} />
        </label>
        <label>
          <span>intent</span>
          <input value={intent} onChange={(event) => onIntentChange(event.target.value)} />
        </label>
        <Button variant="proof" size="sm" leading={<Play size={13} />} disabled={submitting} onClick={onSubmit}>
          {submitting ? "Evaluating" : "Evaluate intent"}
        </Button>
      </div>
      {actionError ? (
        <div className="inline-error" role="alert">
          <AlertCircle size={13} aria-hidden="true" />
          {actionError}
        </div>
      ) : null}
      <div className="lifecycle-rail" aria-label="Governed action lifecycle">
        {LIFECYCLE.map((step, index) => (
          <LifecycleNode key={step} step={step} index={index} receipt={receipt} bootstrap={bootstrap} />
        ))}
      </div>
    </section>
  );
}

function LifecycleNode({
  step,
  index,
  receipt,
  bootstrap,
}: {
  readonly step: (typeof LIFECYCLE)[number];
  readonly index: number;
  readonly receipt: Receipt | null;
  readonly bootstrap: ConsoleBootstrap | null;
}) {
  const verdict = normalizeVerdict(receipt?.status);
  const valueByStep: Record<(typeof LIFECYCLE)[number], string> = {
    Intent: receiptAction(receipt ?? undefined),
    Policy: String(receipt?.metadata?.policy_version ?? "bootstrap-llm-inference"),
    Decision: receipt ? verdict : "pending",
    Receipt: shortHash(receipt?.receipt_id),
    Evidence: bootstrap?.conformance.status ?? "not exported",
  };
  const detailByStep: Record<(typeof LIFECYCLE)[number], string> = {
    Intent: receiptResource(receipt ?? undefined),
    Policy: shortHash(receipt?.output_hash),
    Decision: receipt?.metadata?.reason ? String(receipt.metadata.reason) : "guardian evaluation",
    Receipt: `prev ${shortHash(receipt?.prev_hash)}`,
    Evidence: `L${bootstrap?.conformance.level ?? "0"} · ${bootstrap?.conformance.report_id ?? "no report"}`,
  };
  return (
    <article className={`lifecycle-node lifecycle-node--${verdict}`}>
      <span className="node-index">{String(index + 1).padStart(2, "0")}</span>
      <h3>{step}</h3>
      <strong>{valueByStep[step]}</strong>
      <span>{detailByStep[step]}</span>
    </article>
  );
}

function ReceiptStream({
  receipts,
  selectedId,
  refreshing,
  onRefresh,
  onSelect,
}: {
  readonly receipts: readonly Receipt[];
  readonly selectedId: string | null;
  readonly refreshing: boolean;
  readonly onRefresh: () => void;
  readonly onSelect: (id: string | null) => void;
}) {
  return (
    <section className="receipt-panel" aria-labelledby="receipt-stream-title">
      <div className="panel-head">
        <div>
          <span className="eyebrow">live receipts</span>
          <h2 id="receipt-stream-title">Receipt stream</h2>
        </div>
        <div className="panel-actions">
          <Button variant="ghost" size="sm" leading={<Filter size={13} />}>
            Filters
          </Button>
          <Button variant="secondary" size="sm" leading={<RefreshCw size={13} />} disabled={refreshing} onClick={onRefresh}>
            Refresh
          </Button>
        </div>
      </div>
      <div className="receipt-table-wrap">
        <table className="receipt-table">
          <thead>
            <tr>
              <th>timestamp</th>
              <th>agent</th>
              <th>action</th>
              <th>resource</th>
              <th>verdict</th>
              <th>risk</th>
              <th>receipt</th>
              <th>proof</th>
            </tr>
          </thead>
          <tbody>
            {receipts.length === 0 ? (
              <tr>
                <td colSpan={8} className="empty-cell">
                  No receipts yet. Evaluate an intent to create the first signed receipt.
                </td>
              </tr>
            ) : (
              receipts.map((receipt) => {
                const id = receipt.receipt_id ?? null;
                const selected = id !== null && id === selectedId;
                return (
                  <tr key={id ?? `${receipt.decision_id}-${receipt.lamport_clock}`} className={selected ? "is-selected" : ""} onClick={() => onSelect(id)}>
                    <td>{formatTime(receipt.timestamp)}</td>
                    <td>{receipt.executor_id ?? "anonymous"}</td>
                    <td>{receiptAction(receipt)}</td>
                    <td>{receiptResource(receipt)}</td>
                    <td><VerdictBadge state={normalizeVerdict(receipt.status)} /></td>
                    <td><Badge state={normalizeRisk(receipt)} tone="risk" label={normalizeRisk(receipt)} /></td>
                    <td><code>{shortHash(receipt.receipt_id)}</code></td>
                    <td><VerificationStatus state={verificationState(receipt)} /></td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function SurfaceWorkspace({
  active,
  surface,
  bootstrap,
  receipts,
}: {
  readonly active: string;
  readonly surface: ReturnType<typeof useSurfaceState>;
  readonly bootstrap: ConsoleBootstrap | null;
  readonly receipts: readonly Receipt[];
}) {
  const endpointSource = ENDPOINT_SURFACES[active];
  const source = surface.state?.source ?? endpointSource ?? "not registered";
  const status = surface.state?.status ?? (surface.endpointState ? (surface.endpointState.ok ? "ready" : `http ${surface.endpointState.status}`) : "loading");
  const records = surface.state?.records ?? recordsFromEndpoint(active, surface.endpointState?.data);
  const summary = surface.state?.summary ?? summaryFromEndpoint(active, surface.endpointState);

  return (
    <section className="surface-panel" aria-labelledby="surface-title">
      <div className="panel-head">
        <div>
          <span className="eyebrow">{source}</span>
          <h2 id="surface-title">{surfaceTitle(active)}</h2>
        </div>
        <StatusPill state={status === "ready" ? "verified" : surface.loading ? "pending" : "failed"} label={status} />
      </div>
      {surface.error ? (
        <div className="inline-error" role="alert">
          <AlertCircle size={13} aria-hidden="true" />
          {surface.error}
        </div>
      ) : null}
      <div className="surface-summary">
        <SurfaceSummary label="source" value={source} />
        <SurfaceSummary label="records" value={String(records.length)} />
        <SurfaceSummary label="receipts" value={String(receipts.length)} />
        <SurfaceSummary label="kernel" value={bootstrap?.health.kernel ?? "loading"} />
      </div>
      {summary ? <JsonBlock title="summary" value={summary} /> : null}
      <RecordTable records={records} />
      {surface.endpointState && !surface.endpointState.ok ? (
        <div className="inline-error" role="status">
          <AlertCircle size={13} aria-hidden="true" />
          Backing endpoint returned HTTP {surface.endpointState.status}; this surface is intentionally not showing invented data.
        </div>
      ) : null}
    </section>
  );
}

function surfaceTitle(active: string): string {
  const labels: Record<string, string> = {
    overview: "Overview",
    agents: "Agents from receipts",
    actions: "Actions from receipts",
    approvals: "Approval queue",
    policies: "Policy runtime",
    connectors: "MCP capabilities",
    evidence: "Evidence export",
    replay: "Replay timeline",
    audit: "Audit from receipts",
    developer: "Developer contracts",
    settings: "Runtime settings",
  };
  return labels[active] ?? active;
}

function SurfaceSummary({ label, value }: { readonly label: string; readonly value: string }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function summaryFromEndpoint(active: string, endpoint: { readonly status: number; readonly ok: boolean; readonly data: unknown } | null): Record<string, unknown> | null {
  if (!endpoint) return null;
  if (!endpoint.ok) return { http_status: endpoint.status };
  if (active === "connectors" && isRecord(endpoint.data)) {
    return {
      server_name: endpoint.data.server_name,
      version: endpoint.data.version,
      governance: endpoint.data.governance,
      tool_count: Array.isArray(endpoint.data.tools) ? endpoint.data.tools.length : 0,
    };
  }
  if (active === "evidence" && isRecord(endpoint.data)) {
    return {
      export_type: endpoint.data.type ?? "evidence",
      keys: Object.keys(endpoint.data).length,
    };
  }
  if (active === "replay" && isRecord(endpoint.data)) {
    return endpoint.data;
  }
  return { http_status: endpoint.status };
}

function recordsFromEndpoint(active: string, data: unknown): readonly Record<string, unknown>[] {
  if (!isRecord(data)) return [];
  if (active === "connectors" && Array.isArray(data.tools)) {
    return data.tools.filter(isRecord);
  }
  if (active === "evidence") {
    return Object.entries(data).map(([key, value]) => ({ key, value: formatCellValue(value) }));
  }
  if (active === "replay") {
    if (Array.isArray(data.events)) return data.events.filter(isRecord);
    if (Array.isArray(data.nodes)) return data.nodes.filter(isRecord);
    return Object.entries(data).map(([key, value]) => ({ key, value: formatCellValue(value) }));
  }
  return [];
}

function RecordTable({ records }: { readonly records: readonly Record<string, unknown>[] }) {
  const columns = useMemo(() => {
    const keys = new Set<string>();
    for (const record of records.slice(0, 20)) {
      for (const key of Object.keys(record)) keys.add(key);
    }
    return [...keys].slice(0, 6);
  }, [records]);

  if (records.length === 0) {
    return <div className="empty-state">No records returned by the backing OSS endpoint.</div>;
  }

  return (
    <div className="receipt-table-wrap surface-table-wrap">
      <table className="receipt-table">
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column}>{column}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {records.slice(0, 50).map((record, index) => (
            <tr key={index}>
              {columns.map((column) => (
                <td key={column}>{formatCellValue(record[column])}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function JsonBlock({ title, value }: { readonly title: string; readonly value: unknown }) {
  return (
    <figure className="json-block">
      <figcaption>{title}</figcaption>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </figure>
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function formatCellValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function Inspector({
  bootstrap,
  receipt,
  error,
  replayStatus,
  onReplay,
}: {
  readonly bootstrap: ConsoleBootstrap | null;
  readonly receipt: Receipt | null;
  readonly error: string | null;
  readonly replayStatus: string;
  readonly onReplay: () => void;
}) {
  return (
    <aside className="inspector" aria-labelledby="inspector-title">
      <div className="panel-head">
        <div>
          <span className="eyebrow">selected receipt</span>
          <h2 id="inspector-title">{receipt ? shortHash(receipt.receipt_id) : "No receipt selected"}</h2>
        </div>
        <StatusPill state={verificationState(receipt)} label={verificationState(receipt)} />
      </div>
      {error ? (
        <div className="inline-error" role="alert">
          <XCircle size={13} aria-hidden="true" />
          {error}
        </div>
      ) : null}
      <div className="proof-path">
        <h3>ProofGraph path</h3>
        {["intent", "policy", "decision", "receipt", "evidence"].map((node) => (
          <div key={node} className="proof-node">
            <span>{node}</span>
            <code>
              {node === "intent"
                ? receiptAction(receipt ?? undefined)
                : node === "policy"
                  ? "bootstrap-llm-inference"
                  : node === "decision"
                    ? normalizeVerdict(receipt?.status)
                    : node === "receipt"
                      ? shortHash(receipt?.receipt_id)
                      : bootstrap?.conformance.status ?? "not exported"}
            </code>
          </div>
        ))}
      </div>
      <dl className="inspector-grid">
        <div>
          <dt>decision hash</dt>
          <dd>{receipt?.output_hash ? <HashText value={receipt.output_hash} kind="policy" /> : "not emitted"}</dd>
        </div>
        <div>
          <dt>blob hash</dt>
          <dd>{receipt?.blob_hash ? <HashText value={receipt.blob_hash} /> : "not emitted"}</dd>
        </div>
        <div>
          <dt>signature</dt>
          <dd>{receipt?.signature ? "sig ok" : "pending"}</dd>
        </div>
        <div>
          <dt>replay diff</dt>
          <dd>{replayStatus}</dd>
        </div>
        <div>
          <dt>MCP scopes</dt>
          <dd>{bootstrap?.mcp.scopes.join(", ") || "not configured"}</dd>
        </div>
      </dl>
      <div className="inspector-actions">
        <Button variant="approve" size="sm" disabled={!receipt} leading={<CheckCircle2 size={13} />}>
          Approve
        </Button>
        <Button variant="secondary" size="sm" disabled={!receipt} leading={<RotateCcw size={13} />} onClick={onReplay}>
          Replay
        </Button>
        <Button variant="proof" size="sm" asChild>
          <a href="/api/v1/evidence/soc2" target="_blank" rel="noreferrer">
            <FileArchive size={13} aria-hidden="true" />
            Export evidence
          </a>
        </Button>
      </div>
    </aside>
  );
}

function OperationsStrip({ bootstrap, receipt }: { readonly bootstrap: ConsoleBootstrap | null; readonly receipt: Receipt | null }) {
  const cards = [
    {
      title: "Approvals",
      icon: LockKeyhole,
      value: String(bootstrap?.counts.pending_approvals ?? 0),
      detail: "cryptographic HITL queue",
      state: (bootstrap?.counts.pending_approvals ? "escalate" : "verified") as HelmSemanticState,
    },
    {
      title: "MCP risk",
      icon: ShieldCheck,
      value: bootstrap?.mcp.authorization ?? "unknown",
      detail: bootstrap?.mcp.scopes.join(" · ") || "scopes not configured",
      state: "verified" as HelmSemanticState,
    },
    {
      title: "Conformance",
      icon: ListChecks,
      value: bootstrap?.conformance.level ?? "L0",
      detail: bootstrap?.conformance.status ?? "not reported",
      state: (bootstrap?.conformance.status === "pass" ? "verified" : "pending") as HelmSemanticState,
    },
    {
      title: "Current action",
      icon: Activity,
      value: normalizeVerdict(receipt?.status),
      detail: receipt ? `${receiptAction(receipt)} · ${shortHash(receipt.receipt_id)}` : "waiting for receipt",
      state: normalizeVerdict(receipt?.status) as HelmSemanticState,
    },
  ];
  return (
    <section className="ops-strip" aria-label="Operational modules">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <article key={card.title} className="ops-card">
            <Icon size={15} strokeWidth={1.8} aria-hidden="true" />
            <div>
              <h3>{card.title}</h3>
              <strong>{card.value}</strong>
              <span>{card.detail}</span>
            </div>
            <Badge state={card.state} label={card.state} dot />
          </article>
        );
      })}
    </section>
  );
}
