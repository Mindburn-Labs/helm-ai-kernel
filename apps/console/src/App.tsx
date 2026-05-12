"use client";

import {
  Activity,
  AlertCircle,
  Archive,
  Boxes,
  Braces,
  Command as CommandIcon,
  Database,
  FileArchive,
  FileCheck2,
  FileKey2,
  GitBranch,
  KeyRound,
  ListChecks,
  LockKeyhole,
  Play,
  RefreshCw,
  RotateCcw,
  Search,
  Settings,
  ShieldCheck,
  Terminal,
  UserRound,
  Workflow,
  XCircle,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ComponentType, type ReactNode } from "react";
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
  useTheme,
  type HelmSemanticState,
  type RiskState,
  type VerdictState,
  type VerificationState,
} from "@helm/design-system-core";
import {
  evaluateIntent,
  hasConsoleAdminKey,
  isUnauthorizedError,
  loadBootstrap,
  loadConsoleSurface,
  loadEndpoint,
  loadReceipts,
  replayVerifyCurrentEvidence,
  runPublicDemo,
  setConsoleAdminKey,
  tamperPublicDemoReceipt,
  verifyPublicDemoReceipt,
  watchReceipts,
  type ConsoleBootstrap,
  type DemoRunResult,
  type DemoVerifyResult,
  type ConsoleSurfaceState,
  type Receipt,
} from "./api/client";
import { HelmOssAssistantDrawer } from "./agent/drawer";
import { HelmOssAgentProvider } from "./agent/provider";
import { buildOssAgentState } from "./agent/state";

const DesignSystemErrorBoundary = ErrorBoundary as unknown as ComponentType<{ readonly children: ReactNode }>;

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
      { id: "boundary", label: "Boundary", icon: ShieldCheck },
      { id: "mcp", label: "MCP", icon: GitBranch },
      { id: "sandbox", label: "Sandbox", icon: LockKeyhole },
      { id: "authz", label: "Authz", icon: KeyRound },
      { id: "budgets", label: "Budgets", icon: Database },
      { id: "connectors", label: "Connectors", icon: GitBranch },
      { id: "receipts", label: "Receipts", icon: Archive },
      { id: "evidence", label: "Evidence", icon: FileArchive },
      { id: "replay", label: "Replay", icon: RotateCcw },
      { id: "conformance", label: "Conformance", icon: ListChecks },
      { id: "audit", label: "Audit", icon: Braces },
    ],
  },
  {
    title: "System",
    items: [
      { id: "telemetry", label: "Telemetry", icon: Activity },
      { id: "coexistence", label: "Coexistence", icon: Workflow },
      { id: "developer", label: "Developer", icon: Terminal },
      { id: "settings", label: "Settings", icon: Settings },
    ],
  },
] as const;

const LIFECYCLE = ["Intent", "Policy", "Decision", "Receipt", "Evidence"] as const;
const PROOF_DEMO_ACTIONS = [
  { id: "read_ticket", label: "Read ticket" },
  { id: "draft_reply", label: "Draft reply" },
  { id: "small_refund", label: "Small refund" },
  { id: "large_refund", label: "Large refund" },
  { id: "dangerous_shell", label: "Dangerous shell" },
  { id: "export_customer_list", label: "Export customer list" },
  { id: "modify_policy", label: "Modify policy" },
] as const;

const ENDPOINT_SURFACES: Record<string, string> = {
  agents: "/api/v1/identity/agents",
  approvals: "/api/v1/approvals",
  boundary: "/api/v1/boundary/records",
  mcp: "/api/v1/mcp/registry",
  sandbox: "/api/v1/sandbox/grants",
  authz: "/api/v1/authz/snapshots",
  budgets: "/api/v1/budgets",
  connectors: "/mcp/v1/capabilities",
  evidence: "/api/v1/evidence/envelopes",
  conformance: "/api/v1/conformance/reports",
  telemetry: "/api/v1/telemetry/otel/config",
  coexistence: "/api/v1/coexistence/capabilities",
};

const CONSOLE_SURFACES = new Set(["overview", "actions", "policies", "replay", "audit", "developer", "settings"]);
type ConsoleAccessState = "unknown" | "authorized" | "unauthorized";
type ReceiptStreamState = "connecting" | "live" | "disconnected" | "unauthorized";

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
  const metadata = receipt.metadata;
  const explicitState = normalizeVerificationState(metadata?.verification_status ?? metadata?.verification_state);
  if (explicitState) return explicitState;

  const verification = metadata?.verification;
  if (isRecord(verification)) {
    return normalizeVerificationState(verification.verdict ?? verification.status ?? verification.state) ?? "pending";
  }

  return "pending";
}

function normalizeVerificationState(value: unknown): VerificationState | null {
  const normalized = String(value ?? "").toLowerCase();
  switch (normalized) {
    case "pass":
    case "passed":
    case "verified":
    case "valid":
      return "verified";
    case "fail":
    case "failed":
    case "invalid":
      return "failed";
    case "pending":
    case "checking":
      return "pending";
    case "exported":
      return "exported";
    case "expired":
      return "expired";
    case "unavailable":
      return "unavailable";
    default:
      return null;
  }
}

function signatureSummary(receipt: Receipt | null): string {
  if (!receipt?.signature) return "not emitted";
  const state = verificationState(receipt);
  if (state === "verified") return "verified";
  if (state === "failed") return "verification failed";
  return "present; verification pending";
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

function useConsoleData(authRevision: number) {
  const [bootstrap, setBootstrap] = useState<ConsoleBootstrap | null>(null);
  const [receipts, setReceipts] = useState<readonly Receipt[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [streamState, setStreamState] = useState<ReceiptStreamState>("connecting");
  const [accessState, setAccessState] = useState<ConsoleAccessState>("unknown");
  const [refreshing, setRefreshing] = useState(false);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    setError(null);
    try {
      const [boot, receiptRows] = await Promise.all([loadBootstrap(), loadReceipts(100)]);
      setBootstrap(boot);
      setReceipts(mergeReceipts(boot.receipts, receiptRows));
      setAccessState("authorized");
      setStreamState("live");
    } catch (err) {
      if (isUnauthorizedError(err)) {
        setAccessState("unauthorized");
        setError("Protected Console APIs require HELM_ADMIN_API_KEY and a matching session key.");
        setStreamState("unauthorized");
      } else {
        setAccessState("unknown");
        setError(err instanceof Error ? err.message : "Console data failed to load");
        setStreamState("disconnected");
      }
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [authRevision, refresh]);

  useEffect(() => {
    if (accessState === "unauthorized" && !hasConsoleAdminKey()) {
      setStreamState("unauthorized");
      return undefined;
    }
    const stop = watchReceipts(
      (receipt) => {
        setStreamState("live");
        setReceipts((current) => mergeReceipts(current, [receipt]));
      },
      (err) => {
        if (isUnauthorizedError(err)) {
          setAccessState("unauthorized");
          setError("Receipt streaming requires a valid Console session key.");
          setStreamState("unauthorized");
          return;
        }
        setError(err.message);
        setStreamState("disconnected");
      },
    );
    return stop;
  }, [accessState, authRevision]);

  return { bootstrap, receipts, error, streamState, accessState, refreshing, refresh, setReceipts };
}

function useSurfaceState(active: string, authRevision: number) {
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
  }, [active, authRevision]);

  return { state, endpointState, loading, error };
}

export function App() {
  return (
    <ThemeProvider defaultPreference="dark" defaultDensity="compact">
      <I18nProvider defaultLocale="en-US">
        <TelemetryProvider sink={() => undefined}>
          <DesignSystemErrorBoundary>
            <ConsoleApp />
          </DesignSystemErrorBoundary>
        </TelemetryProvider>
      </I18nProvider>
    </ThemeProvider>
  );
}

function ConsoleApp() {
  const [authRevision, setAuthRevision] = useState(0);
  const { bootstrap, receipts, error, streamState, accessState, refreshing, refresh, setReceipts } = useConsoleData(authRevision);
  const [active, setActive] = useState("command");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [intent, setIntent] = useState("LLM_INFERENCE gpt-4.1-mini");
  const [principal, setPrincipal] = useState("operator@local");
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [demoAction, setDemoAction] = useState<(typeof PROOF_DEMO_ACTIONS)[number]["id"]>("read_ticket");
  const [demoResult, setDemoResult] = useState<DemoRunResult | null>(null);
  const [demoVerify, setDemoVerify] = useState<DemoVerifyResult | null>(null);
  const [demoTamper, setDemoTamper] = useState<DemoVerifyResult | null>(null);
  const [demoError, setDemoError] = useState<string | null>(null);
  const [demoBusy, setDemoBusy] = useState<"run" | "verify" | "tamper" | null>(null);
  const [replayStatus, setReplayStatus] = useState("not checked");
  const [assistantOpen, setAssistantOpen] = useState(false);
  const surface = useSurfaceState(active, authRevision);
  const authChanged = useCallback(() => {
    setAuthRevision((value) => value + 1);
  }, []);

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

  const agentState = useMemo(
    () =>
      buildOssAgentState({
        bootstrap,
        active,
        selectedReceipt,
        query,
        receipts: filteredReceipts,
        demoAction,
        replayStatus,
      }),
    [active, bootstrap, demoAction, filteredReceipts, query, replayStatus, selectedReceipt],
  );

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
      const payload = await replayVerifyCurrentEvidence(selectedReceipt?.executor_id ?? "");
      const replayCheck = payload.checks?.replay ?? payload.checks?.causal_chain;
      setReplayStatus(payload.verdict ?? replayCheck ?? "verified");
    } catch (err) {
      setReplayStatus(err instanceof Error ? err.message : "replay unavailable");
    }
  };

  const runDemoScenario = async () => {
    setDemoBusy("run");
    setDemoError(null);
    setDemoVerify(null);
    setDemoTamper(null);
    try {
      const result = await runPublicDemo(demoAction);
      setDemoResult(result);
    } catch (err) {
      setDemoError(err instanceof Error ? err.message : "Demo run failed");
    } finally {
      setDemoBusy(null);
    }
  };

  const verifyDemoScenario = async () => {
    const receipt = demoResult?.receipt;
    const expectedReceiptHash = demoResult?.proof_refs.receipt_hash;
    if (!receipt) return;
    if (!expectedReceiptHash) {
      setDemoError("Demo receipt hash missing");
      return;
    }
    setDemoBusy("verify");
    setDemoError(null);
    try {
      setDemoVerify(await verifyPublicDemoReceipt(receipt, expectedReceiptHash));
    } catch (err) {
      setDemoError(err instanceof Error ? err.message : "Demo verification failed");
    } finally {
      setDemoBusy(null);
    }
  };

  const tamperDemoScenario = async () => {
    const receipt = demoResult?.receipt;
    const expectedReceiptHash = demoResult?.proof_refs.receipt_hash;
    if (!receipt) return;
    if (!expectedReceiptHash) {
      setDemoError("Demo receipt hash missing");
      return;
    }
    setDemoBusy("tamper");
    setDemoError(null);
    try {
      setDemoTamper(await tamperPublicDemoReceipt(receipt, expectedReceiptHash));
    } catch (err) {
      setDemoError(err instanceof Error ? err.message : "Demo tamper failed");
    } finally {
      setDemoBusy(null);
    }
  };

  return (
    <HelmOssAgentProvider state={agentState}>
      <div className="console-shell">
      <Sidebar active={active} onActiveChange={setActive} counts={bootstrap?.counts} />
      <main className="console-main">
        <Topbar bootstrap={bootstrap} active={active} streamState={streamState} query={query} onQueryChange={setQuery} />
        <div className="assistant-affordance">
          <HelmOssAssistantDrawer
            state={agentState}
            open={assistantOpen}
            onOpenChange={setAssistantOpen}
            onNavigate={setActive}
            onSelectReceipt={setSelectedId}
            onSearchChange={setQuery}
            onDemoActionChange={(action) => {
              if (PROOF_DEMO_ACTIONS.some((item) => item.id === action)) {
                setDemoAction(action as (typeof PROOF_DEMO_ACTIONS)[number]["id"]);
              }
            }}
          />
        </div>
        <section className="console-page" aria-label="HELM Console workspace">
          <AccessBanner accessState={accessState} error={error} onAuthChanged={authChanged} />
          <div className="page-grid">
            <ConsoleIntro active={active} bootstrap={bootstrap} />
            {active === "command" ? (
              <div className="console-stack">
                <ProofDemoSurface
                  action={demoAction}
                  result={demoResult}
                  verifyResult={demoVerify}
                  tamperResult={demoTamper}
                  busy={demoBusy}
                  error={demoError}
                  onActionChange={setDemoAction}
                  onRun={runDemoScenario}
                  onVerify={verifyDemoScenario}
                  onTamper={tamperDemoScenario}
                />
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
    </HelmOssAgentProvider>
  );
}

function AccessBanner({
  accessState,
  error,
  onAuthChanged,
}: {
  readonly accessState: ConsoleAccessState;
  readonly error: string | null;
  readonly onAuthChanged: () => void;
}) {
  const [token, setToken] = useState("");
  const configured = hasConsoleAdminKey();

  if (accessState !== "unauthorized") return null;

  const saveToken = () => {
    setConsoleAdminKey(token);
    setToken("");
    onAuthChanged();
  };
  const clearToken = () => {
    setConsoleAdminKey("");
    setToken("");
    onAuthChanged();
  };

  return (
    <section className="access-banner" aria-labelledby="console-access-title" role="alert">
      <KeyRound size={16} aria-hidden="true" />
      <div>
        <h2 id="console-access-title">Console access required</h2>
        <p id="console-access-detail">
          {error ?? "Protected Console APIs require an admin bearer key."} Set a session key that matches HELM_ADMIN_API_KEY on this runtime.
        </p>
      </div>
      <form
        className="access-form"
        onSubmit={(event) => {
          event.preventDefault();
          saveToken();
        }}
      >
        <label>
          <span>admin key</span>
          <input
            type="password"
            value={token}
            autoComplete="current-password"
            aria-describedby="console-access-detail"
            placeholder={configured ? "session key configured" : "paste session key"}
            onChange={(event) => setToken(event.target.value)}
          />
        </label>
        <Button type="submit" variant="proof" size="sm" disabled={token.trim() === ""}>
          Use key
        </Button>
        <Button type="button" variant="secondary" size="sm" disabled={!configured} onClick={clearToken}>
          Clear
        </Button>
      </form>
    </section>
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
    agents: counts?.mcp_tools,
    approvals: counts?.pending_approvals,
    boundary: counts?.receipts,
    mcp: counts?.mcp_tools,
    sandbox: counts?.receipts,
    authz: counts?.receipts,
    budgets: counts?.pending_approvals,
    receipts: counts?.receipts,
    evidence: counts?.receipts,
    connectors: counts?.mcp_tools,
    conformance: counts?.receipts,
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
  const theme = useTheme();
  const density = theme?.density ?? "compact";

  return (
    <header className="console-topbar">
      <div className="breadcrumbs">
        <span>Console</span>
        <span>/</span>
        <strong>{surfaceTitle(active)}</strong>
      </div>
      <span className="env-chip" aria-label="Workspace environment">
        <Database size={13} aria-hidden="true" />
        {bootstrap?.workspace.organization ?? "local"} · {bootstrap?.workspace.environment ?? "pending"}
      </span>
      <div className="search-field">
        <Search size={13} aria-hidden="true" />
        <input
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          placeholder="Search receipts, agents, policies..."
          aria-label="Search receipts, agents, policies"
        />
      </div>
      <div className="health-chips" aria-label="Kernel health">
        <HealthChip label="kernel" state={bootstrap?.health.kernel ?? "loading"} />
        <HealthChip label="policy" state={bootstrap?.health.policy ?? "loading"} />
        <HealthChip label="store" state={bootstrap?.health.store ?? "loading"} />
        <HealthChip label="stream" state={streamState} />
      </div>
      <div className="density-toggle" role="group" aria-label="Density">
        <span>density</span>
        <button
          type="button"
          className={density === "compact" ? "is-active" : ""}
          aria-pressed={density === "compact"}
          disabled={!theme}
          onClick={() => theme?.setDensity("compact")}
        >
          Compact
        </button>
        <button
          type="button"
          className={density === "comfortable" ? "is-active" : ""}
          aria-pressed={density === "comfortable"}
          disabled={!theme}
          onClick={() => theme?.setDensity("comfortable")}
        >
          Comfortable
        </button>
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

function ProofDemoSurface({
  action,
  result,
  verifyResult,
  tamperResult,
  busy,
  error,
  onActionChange,
  onRun,
  onVerify,
  onTamper,
}: {
  readonly action: (typeof PROOF_DEMO_ACTIONS)[number]["id"];
  readonly result: DemoRunResult | null;
  readonly verifyResult: DemoVerifyResult | null;
  readonly tamperResult: DemoVerifyResult | null;
  readonly busy: "run" | "verify" | "tamper" | null;
  readonly error: string | null;
  readonly onActionChange: (value: (typeof PROOF_DEMO_ACTIONS)[number]["id"]) => void;
  readonly onRun: () => void;
  readonly onVerify: () => void;
  readonly onTamper: () => void;
}) {
  return (
    <section className="proof-demo" aria-labelledby="proof-demo-title">
      <div className="panel-head">
        <div>
          <span className="eyebrow">public proof workflow</span>
          <h2 id="proof-demo-title">Agent tool call boundary</h2>
        </div>
        <Badge state={(normalizeVerdict(result?.verdict) as HelmSemanticState) ?? "pending"} label={result ? result.verdict : "SANDBOX"} dot />
      </div>
      <div className="proof-demo__labels" aria-label="Truth labels">
        {["LIVE", "OSS-BACKED", "SANDBOX", "SAMPLE POLICY"].map((label) => (
          <span key={label}>{label}</span>
        ))}
      </div>
      <div className="proof-demo__loop" aria-label="OSS proof loop">
        {["Agent tool call", "HELM boundary", "ALLOW / DENY / ESCALATE", "Receipt", "Verify", "Tamper fails"].map((label) => (
          <span key={label}>{label}</span>
        ))}
      </div>
      <div className="proof-demo__controls">
        <label>
          <span>sample action</span>
          <select value={action} onChange={(event) => onActionChange(event.target.value as typeof action)}>
            {PROOF_DEMO_ACTIONS.map((item) => (
              <option key={item.id} value={item.id}>{item.label}</option>
            ))}
          </select>
        </label>
        <Button variant="proof" size="sm" leading={<Play size={13} />} disabled={busy !== null} onClick={onRun}>
          {busy === "run" ? "Running" : "Run scenario"}
        </Button>
        <Button variant="secondary" size="sm" disabled={!result || busy !== null} onClick={onVerify}>
          Verify receipt
        </Button>
        <Button variant="secondary" size="sm" disabled={!result || busy !== null} onClick={onTamper}>
          Tamper
        </Button>
      </div>
      {error ? (
        <div className="inline-error" role="alert">
          <AlertCircle size={13} aria-hidden="true" />
          {error}
        </div>
      ) : null}
      <div className="proof-demo__grid">
        <ProofDatum label="verdict" value={result?.verdict ?? "not run"} />
        <ProofDatum label="reason" value={result?.reason_code ?? "not run"} />
        <ProofDatum label="receipt" value={shortHash(result?.receipt.receipt_id)} />
        <ProofDatum label="hash" value={shortHash(result?.proof_refs.receipt_hash)} />
        <ProofDatum label="verify" value={verifyResult ? `${verifyResult.valid ? "valid" : "invalid"} · ${verifyResult.reason}` : "not checked"} />
        <ProofDatum label="tamper" value={tamperResult ? `${tamperResult.valid ? "valid" : "invalid"} · ${shortHash(tamperResult.tampered_hash)}` : "not checked"} />
      </div>
      {result ? <JsonBlock title="receipt" value={result.receipt} /> : null}
    </section>
  );
}

function ProofDatum({ label, value }: { readonly label: string; readonly value: string }) {
  return (
    <div className="proof-demo__datum">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
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
          <Button variant="secondary" size="sm" leading={<RefreshCw size={13} />} disabled={refreshing} onClick={onRefresh}>
            Refresh
          </Button>
        </div>
      </div>
      <div className="receipt-table-wrap">
        <table className="receipt-table" aria-label="Receipt stream">
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
                const rowClassName = [
                  selected ? "is-selected" : "",
                ].filter(Boolean).join(" ");
                return (
                  <tr
                    key={id ?? `${receipt.decision_id}-${receipt.lamport_clock}`}
                    className={rowClassName}
                  >
                    <td>{formatTime(receipt.timestamp)}</td>
                    <td>{receipt.executor_id ?? "anonymous"}</td>
                    <td>{receiptAction(receipt)}</td>
                    <td>{receiptResource(receipt)}</td>
                    <td><VerdictBadge state={normalizeVerdict(receipt.status)} /></td>
                    <td><Badge state={normalizeRisk(receipt)} tone="risk" label={normalizeRisk(receipt)} /></td>
                    <td>
                      {id ? (
                        <Button variant="ghost" size="sm" aria-label={`Select receipt ${shortHash(receipt.receipt_id)}`} onClick={() => onSelect(id)}>
                          <code>{shortHash(receipt.receipt_id)}</code>
                        </Button>
                      ) : (
                        <code>{shortHash(receipt.receipt_id)}</code>
                      )}
                    </td>
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
    boundary: "Boundary records",
    mcp: "MCP quarantine",
    sandbox: "Sandbox grants",
    authz: "Authorization snapshots",
    budgets: "Budget ceilings",
    connectors: "MCP capabilities",
    evidence: "Evidence envelopes",
    replay: "Replay timeline",
    conformance: "Conformance reports",
    audit: "Audit from receipts",
    telemetry: "Telemetry exports",
    coexistence: "Coexistence manifest",
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
  if (Array.isArray(endpoint.data)) {
    const first = endpoint.data.find(isRecord);
    return {
      http_status: endpoint.status,
      records: endpoint.data.length,
      sample_keys: first ? Object.keys(first).slice(0, 8) : [],
    };
  }
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
  if (isRecord(endpoint.data)) {
    return {
      http_status: endpoint.status,
      keys: Object.keys(endpoint.data).length,
      status: endpoint.data.status ?? endpoint.data.verdict ?? endpoint.data.authority ?? endpoint.data.boundary_role,
    };
  }
  return { http_status: endpoint.status };
}

function recordsFromEndpoint(active: string, data: unknown): readonly Record<string, unknown>[] {
  if (Array.isArray(data)) return data.filter(isRecord);
  if (!isRecord(data)) return [];
  if (active === "connectors" && Array.isArray(data.tools)) {
    return data.tools.filter(isRecord);
  }
  const collectionKeys = [
    "records",
    "receipts",
    "capabilities",
    "tools",
    "reports",
    "snapshots",
    "approvals",
    "grants",
    "budgets",
    "events",
    "nodes",
    "items",
  ];
  for (const key of collectionKeys) {
    const value = data[key];
    if (Array.isArray(value)) return value.filter(isRecord);
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
          <dd>{signatureSummary(receipt)}</dd>
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
        <Button variant="secondary" size="sm" disabled={!receipt} leading={<RotateCcw size={13} />} onClick={onReplay}>
          Replay
        </Button>
        <Button variant="proof" size="sm" asChild>
          <a href="/api/v1/evidence/soc2" target="_blank" rel="noreferrer">
            <FileArchive size={13} aria-hidden="true" />
            Export evidence
          </a>
        </Button>
        <Button variant="secondary" size="sm" asChild>
          <a href="/api/v1/conformance/negative" target="_blank" rel="noreferrer">
            <ListChecks size={13} aria-hidden="true" />
            Negative gates
          </a>
        </Button>
        <Button variant="secondary" size="sm" asChild>
          <a href="/api/v1/sandbox/grants/inspect" target="_blank" rel="noreferrer">
            <ShieldCheck size={13} aria-hidden="true" />
            Sandbox grants
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
      title: "MCP quarantine",
      icon: ShieldCheck,
      value: bootstrap?.mcp.authorization ?? "unknown",
      detail: bootstrap?.mcp.scopes.join(" · ") || "approval required",
      state: "verified" as HelmSemanticState,
    },
    {
      title: "Sandbox grants",
      icon: LockKeyhole,
      value: "deny-all",
      detail: "filesystem · env · network",
      state: "verified" as HelmSemanticState,
    },
    {
      title: "Evidence export",
      icon: FileArchive,
      value: "native",
      detail: "DSSE · JWS",
      state: "pending" as HelmSemanticState,
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
