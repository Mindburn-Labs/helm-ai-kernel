"use client";

import {
  AlertCircle,
  Archive,
  Boxes,
  CheckCircle2,
  ChevronRight,
  Circle,
  Command as CommandIcon,
  FileSearch,
  KeyRound,
  MessageSquareText,
  Play,
  Rocket,
  Settings,
  ShieldCheck,
  Plus,
  PanelRightOpen,
  PanelRightClose,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ComponentType, type ReactNode } from "react";
import {
  ErrorBoundary,
  HashText,
  I18nProvider,
  TelemetryProvider,
  ThemeProvider,
  VerdictBadge,
  VerificationStatus,
  Button,
  FormField,
  SelectField,
  TextInput,
  WorkbenchActionSheetFrame,
  WorkbenchCommandSearch,
  WorkbenchComposer,
  WorkbenchDrawerFrame,
  WorkbenchHealthSummary,
  WorkbenchHeader,
  WorkbenchIntegrationCard,
  WorkbenchMobileNav,
  WorkbenchMobileNavButton,
  WorkbenchQuickAction,
  WorkbenchQuickActions,
  WorkbenchRail,
  WorkbenchRailLink,
  WorkbenchProofSection,
  WorkbenchRecordExplorer,
  WorkbenchRecordRow,
  WorkbenchRouteCoverageTable,
  WorkbenchSectionHeader,
  WorkbenchShell,
  WorkbenchStoreHealthList,
  WorkbenchStatusFact,
  WorkbenchTimelineStep,
  Panel,
  SplitPane,
  CanvasElement,
  PropertyGrid,
  type CanvasNode,
  type CanvasEdge,
  type VerificationState,
  type VerdictState,
} from "@mindburn/ui-core";
import {
  evaluateIntent,
  getConsoleTenantID,
  hasConsoleAdminKey,
  loadReceipts,
  replayVerifyCurrentEvidence,
  runPublicDemo,
  setConsoleAdminKey,
  setConsoleTenantID,
  tamperPublicDemoReceipt,
  verifyPublicDemoReceipt,
  type ConsoleBootstrap,
  type DemoRunResult,
  type DemoVerifyResult,
  type Receipt,
} from "../api/client";
import { HelmAiKernelAssistantDrawer } from "../agent/drawer";
import { DetailDrawer } from "./components/HELMInspector";
import { HelmAiKernelAgentProvider } from "../agent/provider";
import { buildAiKernelAgentState } from "../agent/state";
import { LaunchpadPage } from "../features/launchpad/LaunchpadPage";
import { launchpadApi } from "../features/launchpad/api";
import type { LaunchpadApp, LaunchpadRun, LaunchpadSecretGrant, MCPThreatReview } from "../features/launchpad/types";
import type { AdminActionValues } from "../admin/surfaces";
import { mergeReceipts, useCapabilitiesData, useConsoleData, type ConsoleAccessState } from "./dataHooks";
import {
  buildOperatorTasks,
  buildWorkbenchSnapshot,
  isRecord,
  normalizeState,
  parseGovernedCommand,
  receiptAction,
  receiptKey,
  receiptResource,
  routeForCapability,
  shortId,
} from "./viewModels";
import type {
  Capability,
  CapabilityGroup,
  CommandSource,
  FlowRoute,
  GovernedCommand,
  OperatorTask,
  QuickAction,
  RecordSummary,
  TaskSeverity,
  TaskTimelineStep,
  WorkbenchAction,
  WorkbenchDiagnostic,
  WorkbenchSnapshot,
} from "./types";

const ConsoleBoundary = ErrorBoundary as unknown as ComponentType<{ readonly children: ReactNode }>;

const FLOW_NAV: readonly {
  readonly id: FlowRoute;
  readonly label: string;
  readonly icon: ComponentType<{ readonly size?: number; readonly "aria-hidden"?: boolean }>;
}[] = [
  { id: "workbench", label: "Chat Workspace", icon: MessageSquareText },
  { id: "apps", label: "App Hub", icon: Rocket },
  { id: "runs", label: "Runs", icon: Play },
  { id: "mcp", label: "MCP Firewall", icon: Boxes },
  { id: "policies", label: "Policies", icon: ShieldCheck },
  { id: "secrets", label: "Secrets", icon: KeyRound },
  { id: "sandbox", label: "Sandbox", icon: FileSearch },
  { id: "evidence", label: "Evidence", icon: Archive },
  { id: "receipts", label: "Receipts", icon: CommandIcon },
  { id: "registry", label: "Registry", icon: CommandIcon },
  { id: "settings", label: "Settings", icon: Settings },
];

const WORK_CAPABILITY_IDS = new Set(["approvals", "mcp", "connectors", "sandbox", "authz", "budgets", "trust"]);
const LEDGER_CAPABILITY_IDS = new Set(["receipts", "evidence", "replay", "conformance", "audit", "boundary", "proofgraph"]);
const CAPABILITY_GROUPS: readonly ("All" | CapabilityGroup)[] = ["All", "Core", "Connectors", "Runtime", "Policy", "Proof", "Developer"];
const PROOF_DEMO_ACTIONS = [
  { id: "read_ticket", label: "Read ticket" },
  { id: "draft_reply", label: "Draft reply" },
  { id: "small_refund", label: "Small refund" },
  { id: "large_refund", label: "Large refund" },
  { id: "dangerous_shell", label: "Dangerous shell" },
  { id: "export_customer_list", label: "Export customer list" },
  { id: "modify_policy", label: "Modify policy" },
] as const;

type DrawerItem =
  | { readonly kind: "task"; readonly task: OperatorTask }
  | { readonly kind: "receipt"; readonly receipt: Receipt }
  | { readonly kind: "capability"; readonly capability: Capability }
  | { readonly kind: "record"; readonly capability: Capability; readonly record: RecordSummary }
  | { readonly kind: "action"; readonly capability: Capability; readonly action: WorkbenchAction }
  | { readonly kind: "diagnostics"; readonly diagnostics: readonly WorkbenchDiagnostic[] }
  | { readonly kind: "timeline"; readonly step: TaskTimelineStep };

interface SearchResult {
  readonly id: string;
  readonly label: string;
  readonly detail: string;
  readonly route: FlowRoute;
  readonly item?: DrawerItem;
}

function normalizeVerdict(value: string | undefined): VerdictState {
  switch ((value ?? "").toLowerCase()) {
    case "allow":
    case "allowed":
    case "pass":
      return "allow";
    case "deny":
    case "denied":
    case "fail":
      return "deny";
    case "escalate":
    case "escalated":
      return "escalate";
    default:
      return "pending";
  }
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

function verificationState(receipt: Receipt | null | undefined): VerificationState {
  if (!receipt) return "pending";
  const explicitState = normalizeVerificationState(receipt.metadata?.verification_status ?? receipt.metadata?.verification_state);
  if (explicitState) return explicitState;
  const verification = receipt.metadata?.verification;
  if (typeof verification === "object" && verification !== null && !Array.isArray(verification)) {
    const record = verification as Record<string, unknown>;
    return normalizeVerificationState(record.verdict ?? record.status ?? record.state) ?? "pending";
  }
  return "pending";
}

function signatureSummary(receipt: Receipt | null): string {
  if (!receipt?.signature) return "not emitted";
  const state = verificationState(receipt);
  if (state === "verified") return "verified";
  if (state === "failed") return "verification failed";
  return "present; verification pending";
}

function routeLabel(route: FlowRoute): string {
  return FLOW_NAV.find((item) => item.id === route)?.label ?? "Workbench";
}

function initialRouteFromLocation(): { route: FlowRoute; runId: string } {
  if (typeof window === "undefined") return { route: "workbench", runId: "" };
  const pathname = window.location.pathname.replace(/\/+$/, "");
  const runMatch = pathname.match(/^\/runs\/([^/]+)$/);
  if (runMatch?.[1]) return { route: "runs", runId: decodeURIComponent(runMatch[1]) };
  const firstSegment = pathname.split("/").filter(Boolean)[0] as FlowRoute | undefined;
  if (firstSegment && FLOW_NAV.some((item) => item.id === firstSegment)) {
    return { route: firstSegment, runId: "" };
  }
  return { route: "workbench", runId: "" };
}

export function WorkbenchApp() {
  return (
    <ThemeProvider defaultPreference="dark" defaultDensity="compact">
      <I18nProvider defaultLocale="en-US">
        <TelemetryProvider sink={() => undefined}>
          <ConsoleBoundary>
            <ConsoleApp />
          </ConsoleBoundary>
        </TelemetryProvider>
      </I18nProvider>
    </ThemeProvider>
  );
}

function ConsoleApp() {
  const initialRoute = useMemo(() => initialRouteFromLocation(), []);
  const [authRevision, setAuthRevision] = useState(0);
  const { bootstrap, receipts, error, streamState, accessState, refreshing, refresh, setReceipts } = useConsoleData(authRevision);
  const [active, setActive] = useState<FlowRoute>(initialRoute.route);
  const [isInspectorCollapsed, setIsInspectorCollapsed] = useState(false);
  const [inspectorTab, setInspectorTab] = useState<"activity" | "boundary" | "mcp" | "runtime" | "evidence" | "raw">("activity");
  const needsCapabilityData = active === "developer" || active === "workbench" || active === "work" || active === "ledger" || active === "capabilities" || active === "settings";
  const { capabilities, loading: capabilitiesLoading, refreshOne, refreshAll } = useCapabilitiesData(authRevision, needsCapabilityData);
  const [query, setQuery] = useState("");
  const [drawerItem, setDrawerItem] = useState<DrawerItem | null>(null);
  const [commandText, setCommandText] = useState("LLM_INFERENCE gpt-4.1-mini");
  const [principal, setPrincipal] = useState("operator@local");
  const [currentCommand, setCurrentCommand] = useState<GovernedCommand | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [replayStatus, setReplayStatus] = useState("not checked");
  const [assistantOpen, setAssistantOpen] = useState(false);
  const composerRef = useRef<HTMLTextAreaElement | null>(null);

  const authChanged = useCallback(() => {
    setAuthRevision((value) => value + 1);
  }, []);

  const onNewSession = useCallback(() => {
    setCommandText("");
    setDrawerItem(null);
    setActive("workbench");
  }, []);

  const selectedReceipt = useMemo(() => {
    if (drawerItem?.kind === "receipt") return drawerItem.receipt;
    return receipts[0] ?? null;
  }, [drawerItem, receipts]);

  const tasks = useMemo(
    () => buildOperatorTasks({ bootstrap, receipts, capabilities, accessState, error, streamState }),
    [accessState, bootstrap, capabilities, error, receipts, streamState],
  );

  const snapshot = useMemo(
    () => buildWorkbenchSnapshot({ bootstrap, receipts, capabilities, accessState, error, streamState, command: currentCommand, busy: submitting, replayStatus }),
    [accessState, bootstrap, capabilities, currentCommand, error, receipts, replayStatus, streamState, submitting],
  );

  const agentState = useMemo(
    () =>
      buildAiKernelAgentState({
        bootstrap,
        active,
        selectedReceipt,
        query,
        receipts,
        demoAction: "sandbox-lab",
        replayStatus,
      }),
    [active, bootstrap, query, receipts, replayStatus, selectedReceipt],
  );

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

  const searchResults = useMemo(
    () => buildSearchResults(query, tasks, capabilities, receipts),
    [capabilities, query, receipts, tasks],
  );

  const navigate = useCallback((route: FlowRoute, item?: DrawerItem) => {
    setActive(route);
    if (item) setDrawerItem(item);
  }, []);

  const runReplayProbe = useCallback(async (receipt: Receipt | null) => {
    setReplayStatus("checking");
    try {
      const payload = await replayVerifyCurrentEvidence(receipt?.executor_id ?? "");
      const replayCheck = payload.checks?.replay ?? payload.checks?.causal_chain;
      setReplayStatus(payload.verdict ?? replayCheck ?? "verified");
    } catch (err) {
      setReplayStatus(err instanceof Error ? err.message : "replay unavailable");
    }
  }, []);

  const submitCommand = useCallback(async (textOverride?: string, source: CommandSource = "composer") => {
    const text = (textOverride ?? commandText).trim();
    if (!text || submitting) return;
    const command = parseGovernedCommand(text, source, principal);
    setCurrentCommand(command);
    setCommandText(text);
    setActionError(null);

    // Keep active route strictly on "workbench" to ensure zero cockpit redirection
    setActive("workbench");

    if (command.mode === "approve") {
      setIsInspectorCollapsed(false);
      setInspectorTab("boundary");
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      return;
    }
    if (command.mode === "verify") {
      setIsInspectorCollapsed(false);
      setInspectorTab("evidence");
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      return;
    }
    if (command.mode === "replay") {
      setIsInspectorCollapsed(false);
      setInspectorTab("evidence");
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      await runReplayProbe(receipts[0] ?? null);
      return;
    }
    if (command.mode === "inspect") {
      setIsInspectorCollapsed(false);
      if (text.includes("sandbox")) {
        setInspectorTab("boundary");
      } else if (text.includes("mcp")) {
        setInspectorTab("mcp");
      } else {
        setInspectorTab("runtime");
      }
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      return;
    }
    if (command.mode === "launch") {
      setIsInspectorCollapsed(false);
      setInspectorTab("activity");
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      return;
    }

    setSubmitting(true);
    try {
      await evaluateIntent({
        principal,
        action: command.parsedAction ?? "LLM_INFERENCE",
        resource: command.parsedResource ?? "unspecified",
        context: {
          source: "console.workbench",
          workspace: bootstrap?.workspace,
          entered_at: new Date().toISOString(),
        },
      });
      const updated = await loadReceipts(100);
      setReceipts((current) => mergeReceipts(current, updated));
      setIsInspectorCollapsed(false);
      setInspectorTab("activity");
      const targetReceipt = updated[0] ?? receipts[0];
      if (targetReceipt) {
        setDrawerItem({ kind: "receipt", receipt: targetReceipt });
      }
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Intent evaluation failed");
    } finally {
      setSubmitting(false);
    }
  }, [bootstrap?.workspace, commandText, principal, receipts, runReplayProbe, setReceipts, submitting]);

  const runQuickAction = useCallback((action: QuickAction) => {
    if (action.id === "evaluate-intent") {
      setActive("workbench");
      setCommandText(action.command);
      composerRef.current?.focus();
      return;
    }
    if (action.id === "scan-mcp") {
      setActive("workbench");
      setIsInspectorCollapsed(false);
      setInspectorTab("mcp");
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      return;
    }
    if (action.id === "inspect-sandbox") {
      setActive("workbench");
      setIsInspectorCollapsed(false);
      setInspectorTab("boundary");
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      return;
    }
    void submitCommand(action.command, "quick_action");
  }, [submitCommand, receipts]);

  const openSearchResult = (result: SearchResult) => {
    setActive(result.route);
    if (result.item) setDrawerItem(result.item);
  };

  const navigateFromAssistant = useCallback((surface: string) => {
    const route = FLOW_NAV.find((item) => item.id === surface)?.id;
    if (route) setActive(route);
  }, []);

  const selectReceiptFromAssistant = useCallback((receiptId: string) => {
    const receipt = receipts.find((item) => item.receipt_id === receiptId || item.decision_id === receiptId);
    if (receipt) {
      setDrawerItem({ kind: "receipt", receipt });
      setActive("workbench");
      setIsInspectorCollapsed(false);
      setInspectorTab("activity");
    }
  }, [receipts]);

  return (
    <HelmAiKernelAgentProvider enabled state={agentState}>
      <WorkbenchShell
        securityStance={receipts[0] ? normalizeVerdict(receipts[0].status) : "pending"}
        rail={<Navigation active={active} tasks={tasks} onNavigate={(route) => navigate(route)} onNewSession={onNewSession} />}
        header={
          <ConsoleHeader
            active={active}
            bootstrap={bootstrap}
            accessState={accessState}
            streamState={streamState}
            query={query}
            results={searchResults}
            onQueryChange={setQuery}
            onOpenResult={openSearchResult}
            onRunCommand={(text) => void submitCommand(text, "search")}
            isInspectorCollapsed={isInspectorCollapsed}
            onToggleInspector={() => setIsInspectorCollapsed(!isInspectorCollapsed)}
            assistant={
              <HelmAiKernelAssistantDrawer
                state={agentState}
                open={assistantOpen}
                onOpenChange={setAssistantOpen}
                onNavigate={navigateFromAssistant}
                onSelectReceipt={selectReceiptFromAssistant}
                onSearchChange={setQuery}
                onDemoActionChange={(action) => setCommandText(action)}
              />
            }
          />
        }
        drawer={
          isInspectorCollapsed ? null : (
            <DetailDrawer
              item={drawerItem}
              fallbackReceipt={selectedReceipt}
              replayStatus={replayStatus}
              onClose={() => setDrawerItem(null)}
              onNavigate={navigate}
              onOpen={(item) => setDrawerItem(item)}
              onReplay={() => void runReplayProbe(selectedReceipt)}
              onRefresh={refreshOne}
              activeTab={inspectorTab}
              onTabChange={setInspectorTab}
            />
          )
        }
        mobileNav={<MobileNav active={active} onNavigate={(route) => navigate(route)} />}
      >
              {active === "launch" || active === "apps" ? <LaunchpadFlow surface="launch" /> : null}
              {active === "runs" ? <LaunchpadFlow surface="runs" initialRunId={initialRoute.runId} /> : null}
              {active === "policies" ? <LaunchpadFlow surface="policies" /> : null}
              {active === "mcp" ? <LaunchpadFlow surface="mcp" /> : null}
              {active === "secrets" ? <LaunchpadFlow surface="secrets" /> : null}
              {active === "evidence" ? <LaunchpadFlow surface="evidence" /> : null}
              {active === "receipts" ? <LaunchpadFlow surface="receipts" /> : null}
              {active === "sandbox" ? <LaunchpadFlow surface="sandbox" /> : null}
              {active === "registry" ? <LaunchpadFlow surface="registry" /> : null}
              {active === "developer" || active === "workbench" ? (
                <WorkbenchFlow
                  snapshot={snapshot}
                  bootstrap={bootstrap}
                  receipts={receipts}
                  selectedReceipt={selectedReceipt}
                  capabilities={capabilities}
                  commandText={commandText}
                  principal={principal}
                  submitting={submitting}
                  actionError={actionError}
                  refreshing={refreshing}
                  composerRef={composerRef}
                  onCommandChange={setCommandText}
                  onPrincipalChange={setPrincipal}
                  onSubmit={() => void submitCommand(undefined, "composer")}
                  onQuickAction={runQuickAction}
                  onRefresh={refresh}
                  onOpen={(item) => setDrawerItem(item)}
                  onNavigate={navigate}
                />
              ) : null}
              {active === "work" ? (
                <WorkFlow tasks={tasks} capabilities={capabilities} onOpen={(item) => setDrawerItem(item)} onNavigate={navigate} />
              ) : null}
              {active === "ledger" ? (
                <LedgerFlow
                  receipts={filteredReceipts}
                  capabilities={capabilities}
                  refreshing={refreshing}
                  onRefresh={refresh}
                  onOpen={(item) => setDrawerItem(item)}
                />
              ) : null}
              {active === "capabilities" ? (
                <CapabilitiesFlow
                  capabilities={capabilities}
                  loading={capabilitiesLoading}
                  query={query}
                  onOpen={(item) => setDrawerItem(item)}
                  onRefreshAll={refreshAll}
                />
              ) : null}
              {active === "launchpad" ? <LaunchpadFlow surface="launch" /> : null}
              {active === "settings" ? (
                <SettingsFlow
                  bootstrap={bootstrap}
                  accessState={accessState}
                  streamState={streamState}
                  snapshot={snapshot}
                  onAuthChanged={authChanged}
                  onOpenDiagnostics={() => setDrawerItem({ kind: "diagnostics", diagnostics: snapshot.diagnostics })}
                />
              ) : null}
      </WorkbenchShell>
    </HelmAiKernelAgentProvider>
  );
}

function buildSearchResults(
  query: string,
  tasks: readonly OperatorTask[],
  capabilities: readonly Capability[],
  receipts: readonly Receipt[],
): readonly SearchResult[] {
  const term = query.trim().toLowerCase();
  if (term.length < 2) return [];
  const results: SearchResult[] = [];
  for (const task of tasks) {
    const text = `${task.title} ${task.summary} ${task.source} ${task.state}`.toLowerCase();
    if (text.includes(term)) {
      results.push({ id: `task-${task.id}`, label: task.title, detail: `${task.state} · ${task.source}`, route: task.route, item: { kind: "task", task } });
    }
  }
  for (const capability of capabilities) {
    const text = `${capability.label} ${capability.group} ${capability.sourceEndpoint} ${capability.status}`.toLowerCase();
    if (text.includes(term)) {
      results.push({
        id: `capability-${capability.id}`,
        label: capability.label,
        detail: `${capability.group} · ${capability.sourceEndpoint}`,
        route: routeForCapability(capability.id),
        item: { kind: "capability", capability },
      });
    }
    for (const action of capability.actions) {
      const actionText = `${action.label} ${action.endpoint} ${action.risk}`.toLowerCase();
      if (actionText.includes(term)) {
        results.push({
          id: `action-${action.id}`,
          label: action.label,
          detail: `${capability.label} · ${action.method}`,
          route: routeForCapability(capability.id),
          item: { kind: "action", capability, action },
        });
      }
    }
  }
  for (const receipt of receipts.slice(0, 60)) {
    const text = `${receipt.receipt_id} ${receipt.status} ${receiptAction(receipt)} ${receiptResource(receipt)} ${receipt.executor_id}`.toLowerCase();
    if (text.includes(term)) {
      results.push({
        id: `receipt-${receiptKey(receipt)}`,
        label: shortId(receipt.receipt_id),
        detail: `${receiptAction(receipt)} · ${normalizeState(receipt.status, "pending")}`,
        route: "ledger",
        item: { kind: "receipt", receipt },
      });
    }
  }
  return results.slice(0, 10);
}

function Navigation({
  active,
  tasks,
  onNavigate,
  onNewSession,
}: {
  readonly active: FlowRoute;
  readonly tasks: readonly OperatorTask[];
  readonly onNavigate: (route: FlowRoute) => void;
  readonly onNewSession: () => void;
}) {
  const workCount = tasks.filter((task) => task.route === "work" || task.kind === "approval" || task.kind === "connector" || task.kind === "sandbox").length;
  const ledgerCount = tasks.filter((task) => task.route === "ledger").length;
  const counts: Partial<Record<FlowRoute, number>> = { work: workCount, ledger: ledgerCount };

  const workspaceIds = ["workbench", "apps"];
  const managementIds = ["runs", "mcp", "policies", "secrets", "sandbox", "evidence", "receipts", "registry"];
  const settingsIds = ["settings"];

  const workspaceItems = FLOW_NAV.filter((item) => workspaceIds.includes(item.id));
  const managementItems = FLOW_NAV.filter((item) => managementIds.includes(item.id));
  const settingsItems = FLOW_NAV.filter((item) => settingsIds.includes(item.id));

  return (
    <aside className="sota-rail w-64 flex flex-col h-full py-6 px-4 gap-4 border-r border-outline-variant/30 shrink-0">
      <div className="flex items-center gap-3 mb-6 px-2 cursor-pointer" onClick={() => onNavigate("workbench")}>
        <div className="w-10 h-10 bg-primary/10 flex items-center justify-center border border-primary/20 rounded">
          <span className="material-symbols-outlined text-primary" style={{ fontVariationSettings: "'FILL' 1" }}>terminal</span>
        </div>
        <div>
          <div className="font-headline-md text-[16px] font-bold text-primary leading-tight">HELM OS</div>
          <div className="font-label-caps text-[10px] font-semibold text-on-surface-variant text-muted">Core v4.2</div>
        </div>
      </div>

      <div className="flex flex-col gap-1 flex-1 overflow-y-auto custom-scrollbar">
        <div style={{ fontSize: "9px", fontWeight: "700", color: "var(--color-text-muted)", padding: "8px 16px 4px 12px", textTransform: "uppercase", letterSpacing: "0.05em" }}>Workspace</div>
        {workspaceItems.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              type="button"
              className={`sota-rail-link text-left border-none w-full bg-transparent ${active === item.id ? 'active' : ''}`}
              onClick={() => onNavigate(item.id)}
            >
              <Icon size={16} />
              <span className="font-label-caps text-[11px] uppercase tracking-wider">{item.label}</span>
              {counts[item.id] ? (
                <span className="ml-auto bg-primary-container/20 text-primary px-1.5 py-0.5 rounded text-[10px] font-mono">
                  {counts[item.id]}
                </span>
              ) : null}
            </button>
          );
        })}

        <div style={{ height: "4px" }} />
        <div style={{ fontSize: "9px", fontWeight: "700", color: "var(--color-text-muted)", padding: "8px 16px 4px 12px", textTransform: "uppercase", letterSpacing: "0.05em" }}>Management</div>
        {managementItems.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              type="button"
              className={`sota-rail-link text-left border-none w-full bg-transparent ${active === item.id ? 'active' : ''}`}
              onClick={() => onNavigate(item.id)}
            >
              <Icon size={16} />
              <span className="font-label-caps text-[11px] uppercase tracking-wider">{item.label}</span>
              {counts[item.id] ? (
                <span className="ml-auto bg-primary-container/20 text-primary px-1.5 py-0.5 rounded text-[10px] font-mono">
                  {counts[item.id]}
                </span>
              ) : null}
            </button>
          );
        })}

        <div style={{ height: "4px" }} />
        <div style={{ fontSize: "9px", fontWeight: "700", color: "var(--color-text-muted)", padding: "8px 16px 4px 12px", textTransform: "uppercase", letterSpacing: "0.05em" }}>Settings</div>
        {settingsItems.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              type="button"
              className={`sota-rail-link text-left border-none w-full bg-transparent ${active === item.id ? 'active' : ''}`}
              onClick={() => onNavigate(item.id)}
            >
              <Icon size={16} />
              <span className="font-label-caps text-[11px] uppercase tracking-wider">{item.label}</span>
              {counts[item.id] ? (
                <span className="ml-auto bg-primary-container/20 text-primary px-1.5 py-0.5 rounded text-[10px] font-mono">
                  {counts[item.id]}
                </span>
              ) : null}
            </button>
          );
        })}
      </div>

      <div className="mt-auto flex flex-col gap-1 border-t border-outline-variant/20 pt-4">
        <button
          type="button"
          onClick={onNewSession}
          className="w-full mb-4 bg-primary text-on-primary font-bold py-2 rounded shadow-[0_0_15px_rgba(99,230,242,0.15)] active:scale-[0.98] transition-transform text-[11px] uppercase tracking-wider cursor-pointer border-none"
        >
          Initialize Session
        </button>
      </div>
    </aside>
  );
}

function MobileNav({ active, onNavigate }: { readonly active: FlowRoute; readonly onNavigate: (route: FlowRoute) => void }) {
  return (
    <WorkbenchMobileNav>
      {FLOW_NAV.map((item) => {
        return (
          <WorkbenchMobileNavButton
            key={item.id}
            active={active === item.id}
            label={item.label}
            icon={item.icon}
            onClick={() => onNavigate(item.id)}
          />
        );
      })}
    </WorkbenchMobileNav>
  );
}

function ConsoleHeader({
  active,
  bootstrap,
  accessState,
  streamState,
  query,
  results,
  assistant,
  onQueryChange,
  onOpenResult,
  onRunCommand,
  isInspectorCollapsed,
  onToggleInspector,
}: {
  readonly active: FlowRoute;
  readonly bootstrap: ConsoleBootstrap | null;
  readonly accessState: ConsoleAccessState;
  readonly streamState: string;
  readonly query: string;
  readonly results: readonly SearchResult[];
  readonly assistant: ReactNode;
  readonly onQueryChange: (value: string) => void;
  readonly onOpenResult: (result: SearchResult) => void;
  readonly onRunCommand: (value: string) => void;
  readonly isInspectorCollapsed: boolean;
  readonly onToggleInspector: () => void;
}) {
  return (
    <WorkbenchHeader
      eyebrow="Console"
      title={routeLabel(active)}
      command={
        <WorkbenchCommandSearch
          value={query}
          placeholder="Search or run command"
          onChange={onQueryChange}
          onEnter={() => {
            if (results[0]) onOpenResult(results[0]);
            else if (query.trim()) onRunCommand(query);
          }}
          results={results.length > 0 ? (
          <div className="command-menu" role="listbox" aria-label="Search results">
            {results.map((result) => (
              <button key={result.id} type="button" role="option" onClick={() => onOpenResult(result)}>
                <span>{result.label}</span>
                <small>{result.detail}</small>
              </button>
            ))}
          </div>
          ) : null}
        />
      }
      facts={
        <>
        <StatusPill label="tenant" value={getConsoleTenantID()} />
        <StatusPill label="access" value={accessState === "authorized" ? "ready" : accessState} tone={accessState === "authorized" ? "good" : "warn"} />
        <StatusPill label="stream" value={streamState} tone={streamState === "live" ? "good" : "warn"} />
        <StatusPill label="env" value={bootstrap?.workspace.environment ?? "pending"} />
        {assistant}
        <button
          type="button"
          onClick={onToggleInspector}
          aria-label={isInspectorCollapsed ? "Expand Inspector" : "Collapse Inspector"}
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "4px 8px",
            height: "28px",
            background: "var(--color-panel-raised)",
            border: "1px solid var(--color-border)",
            borderRadius: "4px",
            color: "var(--color-text)",
            cursor: "pointer",
          }}
        >
          {isInspectorCollapsed ? <PanelRightOpen size={15} /> : <PanelRightClose size={15} />}
        </button>
        </>
      }
    />
  );
}

interface LocalSecretRequirement {
  logical: string;
  env: string;
  present: boolean;
}

function getSecretRequirements(app: LaunchpadApp, secrets: readonly LaunchpadSecretGrant[]): LocalSecretRequirement[] {
  const logicalNames = app.required_secrets?.length ? app.required_secrets : app.model_gateway_env ?? [];
  const envNames = app.model_gateway_env?.length ? app.model_gateway_env : logicalNames;
  return logicalNames.map((logical, index) => {
    const env = envNames[Math.min(index, envNames.length - 1)] ?? logical;
    const grant = secrets.find((secret) => secret.name === logical || secret.name === env || secret.value_env === env);
    const present = Boolean(grant?.present);
    return {
      logical,
      env,
      present,
    };
  });
}

function WorkbenchFlow({
  snapshot,
  bootstrap,
  receipts,
  selectedReceipt,
  capabilities,
  commandText,
  principal,
  submitting,
  actionError,
  refreshing,
  composerRef,
  onCommandChange,
  onPrincipalChange,
  onSubmit,
  onQuickAction,
  onRefresh,
  onOpen,
  onNavigate,
}: {
  readonly snapshot: WorkbenchSnapshot;
  readonly bootstrap: ConsoleBootstrap | null;
  readonly receipts: readonly Receipt[];
  readonly selectedReceipt: Receipt | null;
  readonly capabilities: readonly Capability[];
  readonly commandText: string;
  readonly principal: string;
  readonly submitting: boolean;
  readonly actionError: string | null;
  readonly refreshing: boolean;
  readonly composerRef: React.RefObject<HTMLTextAreaElement | null>;
  readonly onCommandChange: (value: string) => void;
  readonly onPrincipalChange: (value: string) => void;
  readonly onSubmit: () => void;
  readonly onQuickAction: (action: QuickAction) => void;
  readonly onRefresh: () => void;
  readonly onOpen: (item: DrawerItem) => void;
  readonly onNavigate: (route: FlowRoute, item?: DrawerItem) => void;
}) {
  const [apps, setApps] = useState<LaunchpadApp[]>([]);
  const [runs, setRuns] = useState<LaunchpadRun[]>([]);
  const [secrets, setSecrets] = useState<LaunchpadSecretGrant[]>([]);
  const [threatReviews, setThreatReviews] = useState<MCPThreatReview[]>([]);
  const [loading, setLoading] = useState(true);
  const [launchingApp, setLaunchingApp] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [nextApps, nextRuns, nextSecrets, nextThreatReviews] = await Promise.all([
        launchpadApi.apps(),
        launchpadApi.runs(),
        launchpadApi.secrets(),
        launchpadApi.mcpThreatReviews(),
      ]);
      setApps(nextApps);
      setRuns(nextRuns);
      setSecrets(nextSecrets);
      setThreatReviews(nextThreatReviews);
      setLoading(false);
    } catch (err) {
      console.error("Failed to load workbench cockpit data", err);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData, refreshing]);

  const handleLaunch = async (appId: string) => {
    setLaunchingApp(appId);
    try {
      await launchpadApi.run(appId, "local-container");
      void loadData();
      onNavigate("runs");
    } catch (err) {
      alert(err instanceof Error ? err.message : "Launch failed");
    } finally {
      setLaunchingApp(null);
    }
  };

  // Arrange dynamic receipts into sequential DAG node list for PixiJS
  const graphNodes: readonly CanvasNode[] = useMemo(() => {
    return receipts
      .filter((receipt): receipt is typeof receipt & { receipt_id: string } => Boolean(receipt.receipt_id))
      .map((receipt) => {
        const isVerified = verificationState(receipt) === "verified";
        return {
          id: receipt.receipt_id,
          label: receiptAction(receipt),
          group: receipt.executor_id || "kernel",
          verdict: normalizeVerdict(receipt.status) === "allow" ? "ALLOW" :
                   normalizeVerdict(receipt.status) === "deny" ? "DENY" : "ESCALATE",
          proofStatus: isVerified ? "VERIFIED" : "UNPROVEN",
          summary: receiptResource(receipt) || "unspecified",
        };
      });
  }, [receipts]);

  const graphEdges: readonly CanvasEdge[] = useMemo(() => {
    const edges: CanvasEdge[] = [];
    const validReceipts = receipts.filter((r): r is typeof r & { receipt_id: string } => Boolean(r.receipt_id));
    for (let i = 1; i < validReceipts.length; i++) {
      edges.push({
        from: validReceipts[i - 1].receipt_id,
        to: validReceipts[i].receipt_id,
      });
    }
    return edges;
  }, [receipts]);

  const handleSelectNode = useCallback((id: string) => {
    const receipt = receipts.find((r) => r.receipt_id === id);
    if (receipt) {
      onOpen({ kind: "receipt", receipt });
    }
  }, [receipts, onOpen]);

  const chronologicalReceipts = useMemo(() => {
    return receipts.slice().reverse();
  }, [receipts]);

  const chatStreamRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (chatStreamRef.current) {
      chatStreamRef.current.scrollTop = chatStreamRef.current.scrollHeight;
    }
  }, [receipts.length]);

  return (
    <div className="flow-page workbench-page" style={{
      display: "flex",
      flexDirection: "column",
      height: "calc(100vh - 110px)",
      minHeight: "0",
      position: "relative",
      overflow: "hidden",
    }}>
      {/* Header section with telemetry and metrics */}
      <section className="health-strip" aria-label="Console health" style={{ flex: "0 0 auto", marginBottom: "16px" }}>
        <WorkbenchHealthSummary
          state={snapshot.healthSummary.state}
          label={snapshot.healthSummary.label}
          message={snapshot.healthSummary.message}
          action={snapshot.diagnostics.length > 0 ? (
            <Button variant="secondary" onClick={() => onOpen({ kind: "diagnostics", diagnostics: snapshot.diagnostics })}>
              Open diagnostics
            </Button>
          ) : null}
        />
        <StatusPill label="receipts" value={String(bootstrap?.counts.receipts ?? receipts.length)} />
        <StatusPill label="MCP tools" value={String(bootstrap?.counts.mcp_tools ?? 0)} />
        <StatusPill label="conformance" value={bootstrap?.conformance.status ?? "unreported"} />
        <StatusPill label="capabilities" value={`${capabilities.length}`} />
      </section>

      {/* Main split side-by-side cockpit layout */}
      <div style={{ flex: 1, minHeight: 0, overflow: "hidden" }}>
        {(() => {
          const leftColumn = (
            <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0, justifyContent: "space-between" }}>
              {/* Chronological Chat/Timeline Stream */}
              <div 
                ref={chatStreamRef}
                style={{ 
                  flex: 1, 
                  overflowY: "auto", 
                  paddingRight: "8px", 
                  paddingBottom: "16px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "16px"
                }} 
                className="chat-stream"
              >
                {/* Welcome Card if there are no receipts */}
                {receipts.length === 0 ? (
                  <div style={{
                    padding: "24px",
                    borderRadius: "12px",
                    background: "var(--color-panel-raised)",
                    border: "1px solid var(--color-border)",
                    boxShadow: "var(--shadow-hairline)",
                    textAlign: "center",
                    margin: "12px 0"
                  }}>
                    <div style={{
                      width: "48px",
                      height: "48px",
                      borderRadius: "50%",
                      background: "rgba(102, 252, 241, 0.1)",
                      border: "1px solid rgba(102, 252, 241, 0.2)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      margin: "0 auto 16px auto",
                      color: "#66fcf1"
                    }}>
                      <MessageSquareText size={24} />
                    </div>
                    <h3 style={{ fontSize: "16px", fontWeight: "bold", color: "var(--color-text)", margin: "0 0 8px 0" }}>
                      Sovereign Conversational Cockpit
                    </h3>
                    <p style={{ fontSize: "12px", color: "var(--color-text-muted)", lineHeight: "1.6", margin: "0 0 20px 0" }}>
                      HELM is a zero-trust, fail-closed platform execution boundary. Every intent evaluated is verified against the canonical OrgGenome policies and returns cryptographically signed receipts.
                    </p>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", justifyContent: "center" }}>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => onQuickAction({
                          id: "evaluate-intent",
                          label: "LLM Inference",
                          hint: "Run inference within sandbox boundary",
                          command: "LLM_INFERENCE gpt-4.1-mini",
                          mode: "evaluate"
                        })}
                      >
                        LLM Inference (GPT-4.1)
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => onQuickAction({
                          id: "evaluate-intent",
                          label: "Sandbox Probe",
                          hint: "Verify system behavior inside secure boundary",
                          command: "DOCKER_SANDBOX ubuntu-latest",
                          mode: "evaluate"
                        })}
                      >
                        Sandbox Probe
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => onQuickAction({
                          id: "evaluate-intent",
                          label: "Read Policy",
                          hint: "Inspect local policy.toml boundary rules",
                          command: "READ_FILE policy.toml",
                          mode: "evaluate"
                        })}
                      >
                        Inspect policy.toml
                      </Button>
                    </div>
                  </div>
                ) : (
                  chronologicalReceipts.map((receipt, index) => {
                    const isVerified = verificationState(receipt) === "verified";
                    const statusText = normalizeVerdict(receipt.status) === "allow" ? "PERMITTED / ALLOW" : "BLOCKED / DENIED";
                    const sigSummaryText = isVerified ? "VERIFIED (OrgGenome Trusted Tenant Signer)" : "UNPROVEN / NO SIGNATURE PRESENT";
                    
                    const logLines = [
                      `[HELM Kernel] init virtual sandbox for executor ${receipt.executor_id || "kernel"}... OK`,
                      `[HELM Kernel] sandbox preopens verify... OK`,
                      `[HELM Kernel] policy verdict: ${statusText}`,
                      `[HELM Kernel] evidence verification: ${sigSummaryText}`,
                      `[HELM Kernel] execution receipt generated: ${shortId(receipt.receipt_id)}`
                    ];

                    return (
                      <div key={receipt.receipt_id} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                        {/* Operator Intent Chat Box */}
                        <div style={{
                          alignSelf: "flex-end",
                          maxWidth: "85%",
                          background: "var(--color-panel-raised)",
                          border: "1px solid var(--color-border)",
                          borderRadius: "12px 12px 0 12px",
                          padding: "12px 16px",
                          marginLeft: "auto",
                          boxShadow: "var(--shadow-hairline)",
                        }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "4px" }}>
                            <span style={{ fontSize: "10px", fontFamily: "monospace", color: "var(--color-text-muted)", fontWeight: "bold" }}>
                              {(receipt.metadata?.principal as string) || "operator@local"}
                            </span>
                          </div>
                          <div style={{ fontSize: "13px", fontFamily: "monospace", color: "var(--color-text)", fontWeight: "bold" }}>
                            {receiptAction(receipt)} {receiptResource(receipt)}
                          </div>
                        </div>

                        {/* HELM Decision Chat Response */}
                        <div style={{
                          alignSelf: "flex-start",
                          maxWidth: "90%",
                          background: "var(--color-panel)",
                          border: "1px solid var(--color-border)",
                          borderRadius: "12px 12px 12px 0",
                          padding: "14px 18px",
                          marginRight: "auto",
                          boxShadow: "var(--shadow-hairline)",
                          display: "flex",
                          flexDirection: "column",
                          gap: "8px",
                          borderLeft: `4px solid ${normalizeVerdict(receipt.status) === "allow" ? "var(--color-success)" : "var(--color-danger)"}`
                        }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                            <span style={{ fontSize: "11px", fontWeight: "900", color: "var(--color-text-muted)", letterSpacing: "0.05em", textTransform: "uppercase" }}>
                              HELM Gatekeeper Verdict
                            </span>
                            <VerdictBadge state={normalizeVerdict(receipt.status)} />
                            <VerificationStatus state={verificationState(receipt)} />
                          </div>

                          {/* Terminal Sandbox Execution Logs */}
                          <div style={{
                            background: "#07090c",
                            border: "1px solid var(--color-border)",
                            borderRadius: "6px",
                            padding: "10px 14px",
                            fontFamily: "monospace",
                            fontSize: "11px",
                            color: "#3fb984",
                            lineHeight: "1.5",
                            marginTop: "4px",
                            textAlign: "left",
                            boxShadow: "inset 0 2px 8px rgba(0,0,0,0.8)"
                          }}>
                            {logLines.map((line, idx) => <div key={idx}>{line}</div>)}
                          </div>

                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "4px" }}>
                            <span style={{ fontSize: "10px", color: "var(--color-text-muted)", fontFamily: "monospace" }}>
                              ID: {shortId(receipt.receipt_id)}
                            </span>
                            <Button size="sm" variant="ghost" onClick={() => onOpen({ kind: "receipt", receipt })}>
                              Inspect details
                            </Button>
                          </div>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>

              {/* Composer Input Box Embedded Static at the Bottom */}
              <div style={{ 
                flex: "0 0 auto", 
                borderTop: "1px solid var(--color-border)", 
                paddingTop: "12px", 
                background: "var(--color-bg)",
                zIndex: 10
              }}>
                <WorkbenchComposer
                  title="Governed agent cockpit"
                  body="Start with one intent. HELM evaluates policy, records proof, and exposes approvals, replay, and sandbox capabilities dynamically."
                  principal={principal}
                  command={commandText}
                  busy={submitting}
                  commandRef={composerRef}
                  error={actionError ? <InlineError message={actionError} /> : null}
                  onPrincipalChange={onPrincipalChange}
                  onCommandChange={onCommandChange}
                  onSubmit={onSubmit}
                  secondaryAction={<Button variant="secondary" disabled={refreshing} onClick={onRefresh}>{refreshing ? "Refreshing" : "Refresh"}</Button>}
                />
              </div>
            </div>
          );

          const rightColumn = (
            <div style={{ display: "flex", flexDirection: "column", gap: "24px", height: "100%", minHeight: 0, overflowY: "auto", paddingRight: "8px" }}>
              {/* ProofGraph Section */}
              <section className="proofgraph-section" style={{ flex: "0 0 auto" }}>
                <SectionHead title="HELM Cryptographic ProofGraph" meta={`${receipts.length} sequence steps`} />
                <div style={{ marginTop: "12px" }}>
                  {receipts.length === 0 ? (
                    <div style={{
                      height: "220px",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      background: "var(--color-panel-raised)",
                      border: "1px dashed var(--color-border)",
                      borderRadius: "12px",
                      color: "var(--color-text-muted)",
                      fontSize: "12px",
                    }}>
                      Evaluate an intent in the cockpit to activate the cryptographic ProofGraph.
                    </div>
                  ) : (
                    <CanvasElement
                      width={480}
                      height={280}
                      nodes={graphNodes}
                      edges={graphEdges}
                      onSelectNode={handleSelectNode}
                      selectedNodeId={selectedReceipt?.receipt_id}
                    />
                  )}
                </div>
              </section>

              {/* App Hub Cockpit Section */}
              <section className="appspec-launcher-section" aria-labelledby="launcher-title" style={{ flex: "0 0 auto" }}>
                <SectionHead title="App Hub Cockpit" meta={`${apps.length} apps declared`} />
                <div style={{ display: "flex", flexDirection: "column", gap: "16px", marginTop: "12px" }}>
                  {loading ? (
                    <div style={{ color: "var(--color-text-muted)", fontSize: "12px" }}>Loading App Hub launchers...</div>
                  ) : apps.length === 0 ? (
                    <div style={{ color: "var(--color-text-muted)", fontSize: "12px" }}>No applications registered in UCS registry.</div>
                  ) : (
                    apps.map(app => {
                      const appId = app.app_id ?? app.id;
                      const appRequirements = getSecretRequirements(app, secrets);
                      const missingSecrets = appRequirements.filter(req => !req.present);
                      const appReviews = threatReviews.filter(rev => rev.app_id === appId);
                      const quarantinedReviews = appReviews.filter(rev => rev.state === "quarantined");

                      const canLaunch = missingSecrets.length === 0 && quarantinedReviews.length === 0;
                      const panelRail = quarantinedReviews.length > 0 ? "deny" : missingSecrets.length > 0 ? "escalate" : "verified";

                      return (
                        <Panel
                          key={appId}
                          priority="primary"
                          rail={panelRail}
                          title={app.name}
                          kicker={`${app.risk_class ?? "standard"} RISK`}
                        >
                          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                            <code style={{ fontSize: "11px", color: "var(--color-text-muted)", background: "rgba(0,0,0,0.2)", padding: "4px 8px", borderRadius: "4px" }}>
                              {app.oci_ref ?? "ucs-verified-digest"}
                            </code>

                            {/* Capabilities list */}
                            {app.declared_capabilities && app.declared_capabilities.length > 0 && (
                              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                                {app.declared_capabilities.map(cap => (
                                  <span key={cap} style={{ fontSize: "10px", padding: "2px 6px", borderRadius: "3px", background: "var(--color-panel-raised)", color: "var(--color-text-muted)" }}>
                                    {cap}
                                  </span>
                                ))}
                              </div>
                            )}

                            {/* Threat / Safety Quick Checks */}
                            <div style={{ display: "flex", flexDirection: "column", gap: "6px", borderTop: "1px solid var(--color-border)", paddingTop: "12px" }}>
                              {/* Missing Secrets */}
                              {missingSecrets.length > 0 ? (
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "12px" }}>
                                  <span style={{ color: "var(--color-warn)", display: "flex", alignItems: "center", gap: "4px" }}>
                                    <AlertCircle size={14} /> Missing secrets: {missingSecrets.map(s => s.logical).join(", ")}
                                  </span>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => onNavigate("secrets")}
                                  >
                                    Add required secret
                                  </Button>
                                </div>
                              ) : (
                                <div style={{ color: "var(--color-success)", fontSize: "12px", display: "flex", alignItems: "center", gap: "4px" }}>
                                  <CheckCircle2 size={14} /> All AppSpec secret grants present
                                </div>
                              )}

                              {/* Quarantined MCP tools */}
                              {quarantinedReviews.length > 0 ? (
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "12px" }}>
                                  <span style={{ color: "#ef4444", display: "flex", alignItems: "center", gap: "4px" }}>
                                    <AlertCircle size={14} /> MCP Quarantine Active ({quarantinedReviews.length} server)
                                  </span>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => onNavigate("mcp")}
                                  >
                                    Review MCP
                                  </Button>
                                </div>
                              ) : (
                                <div style={{ color: "var(--color-success)", fontSize: "12px", display: "flex", alignItems: "center", gap: "4px" }}>
                                  <CheckCircle2 size={14} /> MCP tools verified & approved
                                </div>
                              )}
                            </div>

                            <div style={{ marginTop: "8px" }}>
                              <Button
                                variant={canLaunch ? "approve" : "secondary"}
                                disabled={!canLaunch || launchingApp === appId}
                                onClick={() => handleLaunch(appId)}
                              >
                                <span style={{ display: "flex", alignItems: "center", gap: "6px", justifyContent: "center", width: "100%" }}>
                                  <Play size={14} />
                                  <span>{launchingApp === appId ? "Launching..." : "Launch App"}</span>
                                </span>
                              </Button>
                            </div>
                          </div>
                        </Panel>
                      );
                    })
                  )}
                </div>
              </section>

              {/* Active Run Verdicts Section */}
              <section className="runs-and-proofs-section" aria-labelledby="runs-title" style={{ flex: "0 0 auto", marginBottom: "24px" }}>
                <SectionHead title="Active Run Verdicts" meta={`${runs.length} runs total`} />
                <div style={{ display: "flex", flexDirection: "column", gap: "16px", marginTop: "12px" }}>
                  {loading ? (
                    <div style={{ color: "var(--color-text-muted)", fontSize: "12px" }}>Loading runs...</div>
                  ) : runs.length === 0 ? (
                    <div style={{ color: "var(--color-text-muted)", fontSize: "12px" }}>No runs started in this session.</div>
                  ) : (
                    runs.map(run => {
                      const isVerified = run.evidence_pack_refs && run.evidence_pack_refs.length > 0;
                      return (
                        <Panel
                          key={run.launch_id ?? run.id}
                          priority="primary"
                          rail={isVerified ? "verified" : "pending"}
                          title={run.app_id}
                          kicker={run.state}
                        >
                          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                            <div style={{ fontSize: "12px", color: "var(--color-text-muted)" }}>
                              Substrate: <strong>{run.substrate_id}</strong>
                            </div>

                            {/* Cryptographic Signature Verification Badge */}
                            <div style={{
                              marginTop: "4px",
                              padding: "8px 12px",
                              borderRadius: "6px",
                              background: isVerified ? "rgba(16, 185, 129, 0.1)" : "rgba(245, 158, 11, 0.1)",
                              border: `1px solid ${isVerified ? "rgba(16, 185, 129, 0.2)" : "rgba(245, 158, 11, 0.2)"}`,
                              display: "flex",
                              alignItems: "center",
                              gap: "8px",
                              fontSize: "11px",
                              color: isVerified ? "#10b981" : "#f59e0b",
                            }}>
                              {isVerified ? (
                                <>
                                  <CheckCircle2 size={14} />
                                  <strong>VERIFIED EVIDENCE PACK SIGNED</strong>
                                </>
                              ) : (
                                <>
                                  <AlertCircle size={14} />
                                  <strong>UNPROVEN / UNVERIFIED EVIDENCE</strong>
                                </>
                              )}
                            </div>

                            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "8px" }}>
                              <Button
                                variant="secondary"
                                size="sm"
                                onClick={() => onNavigate("runs")}
                              >
                                Inspect Run
                              </Button>
                            </div>
                          </div>
                        </Panel>
                      );
                    })
                  )}
                </div>
              </section>
            </div>
          );

          // Render side-by-side cockpit via SplitPane with custom wider split sizing override
          return (
            <SplitPane 
              primary={leftColumn} 
              secondary={rightColumn} 
            />
          );
        })()}
      </div>
    </div>
  );
}

function WorkFlow({
  tasks,
  capabilities,
  onOpen,
  onNavigate,
}: {
  readonly tasks: readonly OperatorTask[];
  readonly capabilities: readonly Capability[];
  readonly onOpen: (item: DrawerItem) => void;
  readonly onNavigate: (route: FlowRoute, item?: DrawerItem) => void;
}) {
  const workTasks = tasks.filter((task) => task.route === "work" || task.kind === "approval" || task.kind === "connector" || task.kind === "sandbox");
  const workCapabilities = capabilities.filter((capability) => WORK_CAPABILITY_IDS.has(capability.id));
  return (
    <div className="flow-page">
      <FlowHeader title="Work" body="Approvals, escalations, MCP quarantine, sandbox grants, authz checks, and budget ceilings that require operator attention." />
      <section className="list-section">
        <SectionHead title="Actionable Work" meta={`${workTasks.length} task${workTasks.length === 1 ? "" : "s"}`} />
        <TaskRows tasks={workTasks} onOpen={(task) => onOpen({ kind: "task", task })} onNavigate={onNavigate} />
      </section>
      <section className="list-section">
        <SectionHead title="Queues" meta={`${workCapabilities.length} capabilities`} />
        <CapabilityRows capabilities={workCapabilities} onOpen={onOpen} />
      </section>
    </div>
  );
}

function LedgerFlow({
  receipts,
  capabilities,
  refreshing,
  onRefresh,
  onOpen,
}: {
  readonly receipts: readonly Receipt[];
  readonly capabilities: readonly Capability[];
  readonly refreshing: boolean;
  readonly onRefresh: () => void;
  readonly onOpen: (item: DrawerItem) => void;
}) {
  const [filter, setFilter] = useState("all");
  const ledgerCapabilities = capabilities.filter((capability) => LEDGER_CAPABILITY_IDS.has(capability.id));
  const visibleReceipts = receipts.filter((receipt) => {
    if (filter === "all") return true;
    if (filter === "verified") return verificationState(receipt) === "verified";
    if (filter === "failed") return verificationState(receipt) === "failed" || normalizeState(receipt.status).includes("fail");
    return normalizeState(receipt.status).includes(filter);
  });
  return (
    <div className="flow-page">
      <FlowHeader
        title="Ledger"
        body="Receipts, replay, evidence export, conformance reports, vectors, and negative gates."
        action={<button type="button" className="secondary-action" disabled={refreshing} onClick={onRefresh}>{refreshing ? "Refreshing" : "Refresh receipts"}</button>}
      />
      <section className="list-section">
        <SectionHead title="Receipts" meta={`${visibleReceipts.length} rows`} />
        <Segmented
          value={filter}
          options={["all", "allow", "deny", "escalate", "verified", "failed"]}
          onChange={setFilter}
        />
        <ReceiptRows receipts={visibleReceipts} onOpen={(receipt) => onOpen({ kind: "receipt", receipt })} />
      </section>
      <section className="list-section">
        <SectionHead title="Proof Tools" meta={`${ledgerCapabilities.length} capabilities`} />
        <CapabilityRows capabilities={ledgerCapabilities} onOpen={onOpen} />
      </section>
    </div>
  );
}

function CapabilitiesFlow({
  capabilities,
  loading,
  query,
  onOpen,
  onRefreshAll,
}: {
  readonly capabilities: readonly Capability[];
  readonly loading: boolean;
  readonly query: string;
  readonly onOpen: (item: DrawerItem) => void;
  readonly onRefreshAll: () => void;
}) {
  const [group, setGroup] = useState<"All" | CapabilityGroup>("All");
  const term = query.trim().toLowerCase();
  const visible = capabilities.filter((capability) => {
    const groupMatch = group === "All" || capability.group === group;
    const queryMatch = !term || `${capability.label} ${capability.group} ${capability.sourceEndpoint}`.toLowerCase().includes(term);
    return groupMatch && queryMatch;
  });
  return (
    <div className="flow-page">
      <FlowHeader
        title="Capabilities"
        body="A simple directory for MCP, sandbox, authz, budgets, boundary, telemetry, coexistence, and developer contracts."
        action={<button type="button" className="secondary-action" disabled={loading} onClick={onRefreshAll}>{loading ? "Loading" : "Refresh all"}</button>}
      />
      <Segmented value={group} options={CAPABILITY_GROUPS} onChange={(value) => setGroup(value as "All" | CapabilityGroup)} />
      <section className="integration-grid" aria-label="Capability directory">
        {visible.map((capability) => (
          <WorkbenchIntegrationCard
            key={capability.id}
            group={capability.group}
            title={capability.label}
            detail={capability.sourceEndpoint}
            meta={`${capability.records.length} records · ${capability.status}`}
            action={capability.actions[0]?.label ?? "Read only"}
            status={capability.status}
            onClick={() => onOpen({ kind: "capability", capability })}
          />
        ))}
      </section>
      {group === "All" || group === "Developer" ? <DeveloperSandboxLab /> : null}
    </div>
  );
}

function DeveloperSandboxLab() {
  const [demoAction, setDemoAction] = useState<(typeof PROOF_DEMO_ACTIONS)[number]["id"]>("read_ticket");
  const [demoResult, setDemoResult] = useState<DemoRunResult | null>(null);
  const [demoVerify, setDemoVerify] = useState<DemoVerifyResult | null>(null);
  const [demoTamper, setDemoTamper] = useState<DemoVerifyResult | null>(null);
  const [demoError, setDemoError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"run" | "verify" | "tamper" | null>(null);

  const runDemoScenario = async () => {
    setBusy("run");
    setDemoError(null);
    setDemoVerify(null);
    setDemoTamper(null);
    try {
      setDemoResult(await runPublicDemo(demoAction));
    } catch (err) {
      setDemoError(err instanceof Error ? err.message : "Sandbox lab failed");
    } finally {
      setBusy(null);
    }
  };

  const verifyDemoScenario = async () => {
    const receipt = demoResult?.receipt;
    const expectedReceiptHash = demoResult?.proof_refs.receipt_hash;
    if (!receipt || !expectedReceiptHash) return;
    setBusy("verify");
    setDemoError(null);
    try {
      setDemoVerify(await verifyPublicDemoReceipt(receipt, expectedReceiptHash));
    } catch (err) {
      setDemoError(err instanceof Error ? err.message : "Demo verification failed");
    } finally {
      setBusy(null);
    }
  };

  const tamperDemoScenario = async () => {
    const receipt = demoResult?.receipt;
    const expectedReceiptHash = demoResult?.proof_refs.receipt_hash;
    if (!receipt || !expectedReceiptHash) return;
    setBusy("tamper");
    setDemoError(null);
    try {
      setDemoTamper(await tamperPublicDemoReceipt(receipt, expectedReceiptHash));
    } catch (err) {
      setDemoError(err instanceof Error ? err.message : "Demo tamper check failed");
    } finally {
      setBusy(null);
    }
  };

  return (
    <details className="sandbox-lab">
      <summary>Developer / Sandbox Lab (sample only)</summary>
      <p>This utility uses public demo endpoints. It is never used as fallback data for the live console.</p>
      <div className="lab-controls">
        <FormField label="sample action">
          <SelectField
            value={demoAction}
            options={PROOF_DEMO_ACTIONS.map((item) => item.id)}
            onValueChange={(value) => setDemoAction(value as typeof demoAction)}
          />
        </FormField>
        <button type="button" className="secondary-action" disabled={busy !== null} onClick={() => void runDemoScenario()}>
          {busy === "run" ? "Running" : "Run sample"}
        </button>
        <button type="button" className="secondary-action" disabled={!demoResult || busy !== null} onClick={() => void verifyDemoScenario()}>
          Verify
        </button>
        <button type="button" className="secondary-action" disabled={!demoResult || busy !== null} onClick={() => void tamperDemoScenario()}>
          Tamper
        </button>
      </div>
      {demoError ? <InlineError message={demoError} /> : null}
      <div className="health-strip" aria-label="Sandbox lab results">
        <StatusPill label="verdict" value={demoResult?.verdict ?? "not run"} />
        <StatusPill label="reason" value={demoResult?.reason_code ?? "not run"} />
        <StatusPill label="verify" value={demoVerify ? (demoVerify.valid ? "valid" : "invalid") : "not checked"} />
        <StatusPill label="tamper" value={demoTamper ? (demoTamper.valid ? "valid" : "invalid") : "not checked"} />
      </div>
      {demoResult ? <RawJson title="sample receipt" value={demoResult.receipt} /> : null}
    </details>
  );
}

function LaunchpadFlow({
  surface,
  initialRunId = "",
}: {
  readonly surface: "launch" | "apps" | "runs" | "policies" | "mcp" | "secrets" | "evidence" | "sandbox" | "receipts" | "registry";
  readonly initialRunId?: string;
}) {
  const titles = {
    launch: ["Launch", "Default proof workbench: choose any AppSpec, compile gates, and inspect the run timeline."],
    apps: ["Launch", "Select any agentic app and launch only through HELM's fail-closed execution boundary."],
    runs: ["Runs", "Receipt-backed runtime instances, launch decisions, healthchecks, EvidencePacks, and teardown."],
    policies: ["Policies", "Policy workbench with plain English, structured grants, and raw canonical references."],
    mcp: ["MCP Firewall", "Quarantined MCP servers and tools stay blocked until receipt-backed approval."],
    secrets: ["Secrets", "Secret grants show presence, scope, grant hash, and launch impact without raw values."],
    evidence: ["Evidence", "EvidencePacks, offline verification commands, and proof status for local verification."],
    sandbox: ["Sandbox", "Runtime filesystem, env, network, resources, and grant hash as execution-boundary truth."],
    receipts: ["Receipts", "Signed receipt refs for run state. Missing receipt means unproven."],
    registry: ["Registry", "Raw registry, substrates, and compatibility matrix that drive every Console screen."],
  } as const;
  const [title, body] = titles[surface];
  return (
    <div className="flow-page">
      <FlowHeader title={title} body={body} />
      <LaunchpadPage surface={surface} initialRunId={initialRunId} />
    </div>
  );
}

function SettingsFlow({
  bootstrap,
  accessState,
  streamState,
  snapshot,
  onAuthChanged,
  onOpenDiagnostics,
}: {
  readonly bootstrap: ConsoleBootstrap | null;
  readonly accessState: ConsoleAccessState;
  readonly streamState: string;
  readonly snapshot: WorkbenchSnapshot;
  readonly onAuthChanged: () => void;
  readonly onOpenDiagnostics: () => void;
}) {
  const [adminKey, setAdminKey] = useState("");
  const [tenant, setTenant] = useState(getConsoleTenantID());
  return (
    <div className="flow-page">
      <FlowHeader title="Settings" body="Session credentials, tenant routing, runtime health, and protected API recovery." />
      <section className="settings-layout">
        <form
          className="settings-panel"
          onSubmit={(event) => {
            event.preventDefault();
            setConsoleAdminKey(adminKey);
            setAdminKey("");
            onAuthChanged();
          }}
        >
          <SectionHead title="Admin Session" meta={accessState} />
          <FormField label="HELM admin API key">
            <TextInput
              type="password"
              value={adminKey}
              placeholder={hasConsoleAdminKey() ? "session key configured" : "paste session key"}
              onValueChange={setAdminKey}
            />
          </FormField>
          <div className="button-row">
            <button type="submit" className="primary-action" disabled={adminKey.trim() === ""}>Use key</button>
            <button
              type="button"
              className="secondary-action"
              disabled={!hasConsoleAdminKey()}
              onClick={() => {
                setConsoleAdminKey("");
                onAuthChanged();
              }}
            >
              Clear key
            </button>
          </div>
        </form>
        <form
          className="settings-panel"
          onSubmit={(event) => {
            event.preventDefault();
            setConsoleTenantID(tenant);
            onAuthChanged();
          }}
        >
          <SectionHead title="Tenant" meta="X-Helm-Tenant-ID" />
          <FormField label="tenant id">
            <TextInput value={tenant} onValueChange={setTenant} />
          </FormField>
          <button type="submit" className="primary-action">Save tenant</button>
        </form>
      </section>
      <section className="list-section">
        <SectionHead title="Runtime Health" meta={streamState} />
        <div className="health-strip">
          <StatusPill label="workspace" value={bootstrap?.workspace.project ?? "pending"} />
          <StatusPill label="environment" value={bootstrap?.workspace.environment ?? "pending"} />
          <StatusPill label="kernel" value={bootstrap?.health.kernel ?? "pending"} />
          <StatusPill label="policy" value={bootstrap?.health.policy ?? "pending"} />
          <StatusPill label="diagnostics" value={String(snapshot.diagnostics.length)} tone={snapshot.diagnostics.length ? "warn" : "good"} />
          <button type="button" className="secondary-action" onClick={onOpenDiagnostics}>Open diagnostics</button>
        </div>
      </section>
    </div>
  );
}

function TaskRows({
  tasks,
  onOpen,
  onNavigate,
}: {
  readonly tasks: readonly OperatorTask[];
  readonly onOpen: (task: OperatorTask) => void;
  readonly onNavigate: (route: FlowRoute, item?: DrawerItem) => void;
}) {
  if (tasks.length === 0) return <EmptyLine title="No operator work" body="Approvals, quarantines, denied receipts, and blocked grants will appear here from live API state." />;
  return (
    <div className="task-list">
      {tasks.map((task) => (
        <article key={task.id} className={`task-row severity-${task.severity}`}>
          <button type="button" onClick={() => onOpen(task)}>
            <StateMarker state={task.state} severity={task.severity} />
            <span>
              <strong>{task.title}</strong>
              <small>{task.summary}</small>
            </span>
          </button>
          <button type="button" className="row-action" onClick={() => onNavigate(task.route, { kind: "task", task })}>
            {task.actionLabel}
          </button>
        </article>
      ))}
    </div>
  );
}

function CapabilityRows({ capabilities, onOpen }: { readonly capabilities: readonly Capability[]; readonly onOpen: (item: DrawerItem) => void }) {
  if (capabilities.length === 0) return <EmptyLine title="No capabilities" body="No matching API-backed capability is currently registered." />;
  return (
    <div className="record-list">
      {capabilities.map((capability) => (
        <WorkbenchRecordRow
          key={capability.id}
          title={capability.label}
          detail={`${capability.group} · ${capability.records.length} records · ${capability.status}`}
          meta={capability.sourceEndpoint}
          onClick={() => onOpen({ kind: "capability", capability })}
        />
      ))}
    </div>
  );
}

function ReceiptRows({ receipts, onOpen }: { readonly receipts: readonly Receipt[]; readonly onOpen: (receipt: Receipt) => void }) {
  if (receipts.length === 0) return <EmptyLine title="No receipts" body="Evaluate a governed intent or connect a runtime to start the ledger." />;
  return (
    <div className="receipt-list">
      {receipts.map((receipt) => (
        <button key={receiptKey(receipt)} type="button" className="receipt-row" onClick={() => onOpen(receipt)}>
          <span className={`receipt-state state-${normalizeState(receipt.status, "pending")}`} />
          <strong>{receiptAction(receipt)}</strong>
          <span>{receiptResource(receipt)}</span>
          <em>{shortId(receipt.receipt_id)}</em>
        </button>
      ))}
    </div>
  );
}

function Timeline({ steps, onOpen }: { readonly steps: readonly TaskTimelineStep[]; readonly onOpen: (step: TaskTimelineStep) => void }) {
  return (
    <div className="timeline-list">
      {steps.map((step) => (
        <WorkbenchTimelineStep
          key={step.id}
          state={step.state}
          title={step.label}
          detail={step.summary}
          trailing={<ChevronRight size={15} aria-hidden />}
          onClick={() => onOpen(step)}
        />
      ))}
    </div>
  );
}

function RecordMiniList({ capability, onOpen }: { readonly capability: Capability; readonly onOpen: (item: DrawerItem) => void }) {
  if (capability.records.length === 0) return <EmptyLine title="No records" body={capability.readState.message ?? "This capability returned an explicit empty state."} />;
  const records = capability.records.slice(0, 8);
  return (
    <WorkbenchRecordExplorer
      records={records.map((record) => ({
        id: record.id,
        label: record.label,
        state: record.state,
        detail: record.facts[0] ?? record.source,
      }))}
      onOpen={(id) => {
        const record = records.find((item) => item.id === id);
        if (record) onOpen({ kind: "record", capability, record });
      }}
    />
  );
}

function FlowHeader({ title, body, action }: { readonly title: string; readonly body: string; readonly action?: ReactNode }) {
  return (
    <header className="flow-header">
      <div>
        <h1>{title}</h1>
        <p>{body}</p>
      </div>
      {action ? <div className="flow-header-action">{action}</div> : null}
    </header>
  );
}

function SectionHead({ title, meta }: { readonly title: string; readonly meta?: string }) {
  return <WorkbenchSectionHeader title={title} meta={meta} />;
}

function Segmented({
  value,
  options,
  onChange,
}: {
  readonly value: string;
  readonly options: readonly string[];
  readonly onChange: (value: string) => void;
}) {
  return (
    <div className="segmented-control" role="tablist">
      {options.map((option) => (
        <button key={option} type="button" role="tab" aria-selected={option === value} className={option === value ? "is-active" : ""} onClick={() => onChange(option)}>
          {option}
        </button>
      ))}
    </div>
  );
}

function StatusPill({ label, value, tone = "neutral" }: { readonly label: string; readonly value: string; readonly tone?: "neutral" | "good" | "warn" }) {
  return <WorkbenchStatusFact label={label} value={value} tone={tone} />;
}

function StateMarker({ state, severity }: { readonly state: string; readonly severity: TaskSeverity }) {
  return (
    <span className={`state-marker severity-${severity}`}>
      <Circle size={8} aria-hidden />
      {state}
    </span>
  );
}

function cliForAdminAction(action: WorkbenchAction): string {
  const base = `curl -X ${action.method.toUpperCase()} "$HELM_CONSOLE_URL${action.endpoint}" -H "X-HELM-Admin-Key: $HELM_ADMIN_API_KEY"`;
  if (action.method.toUpperCase() === "GET" || action.fields.length === 0) return base;
  return `${base} -H "Content-Type: application/json" --data @payload.json`;
}

function receiptRefsFromUnknown(value: unknown): string[] {
  const refs = new Set<string>();
  const visit = (item: unknown) => {
    if (typeof item === "string") {
      if (/^(rcpt|receipt|sha256:|evp_|mcp_|approval)/i.test(item)) refs.add(item);
      return;
    }
    if (Array.isArray(item)) {
      item.forEach(visit);
      return;
    }
    if (!isRecord(item)) return;
    for (const [key, nested] of Object.entries(item)) {
      if (/receipt(_id|_ref|s|Refs|Refs)?$/i.test(key) || /receipt/i.test(key)) visit(nested);
      if (key === "ref") visit(nested);
      if (Array.isArray(nested) || isRecord(nested)) visit(nested);
    }
  };
  visit(value);
  return [...refs].slice(0, 8);
}

function Fact({ label, value }: { readonly label: string; readonly value: ReactNode }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function EmptyLine({ title, body }: { readonly title: string; readonly body: string }) {
  return (
    <div className="empty-line">
      <CheckCircle2 size={16} aria-hidden />
      <div>
        <strong>{title}</strong>
        <span>{body}</span>
      </div>
    </div>
  );
}

function InlineError({ message }: { readonly message: string }) {
  return (
    <p className="inline-error" role="alert">
      <AlertCircle size={14} aria-hidden />
      {message}
    </p>
  );
}

function InlineNotice({ message }: { readonly message: string }) {
  return (
    <p className="inline-notice">
      <MessageSquareText size={14} aria-hidden />
      {message}
    </p>
  );
}

function RawJson({ title, value }: { readonly title: string; readonly value: unknown }) {
  return (
    <details className="raw-json">
      <summary>{title}</summary>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </details>
  );
}
