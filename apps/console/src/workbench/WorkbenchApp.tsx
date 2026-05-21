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
} from "lucide-react";
import { useCallback, useMemo, useRef, useState, type ComponentType, type ReactNode } from "react";
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
import { HelmAiKernelAgentProvider } from "../agent/provider";
import { buildAiKernelAgentState } from "../agent/state";
import { LaunchpadPage } from "../features/launchpad/LaunchpadPage";
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
  { id: "launch", label: "Launch", icon: Rocket },
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
  if (typeof window === "undefined") return { route: "launch", runId: "" };
  const pathname = window.location.pathname.replace(/\/+$/, "");
  const runMatch = pathname.match(/^\/runs\/([^/]+)$/);
  if (runMatch?.[1]) return { route: "runs", runId: decodeURIComponent(runMatch[1]) };
  const firstSegment = pathname.split("/").filter(Boolean)[0] as FlowRoute | undefined;
  if (firstSegment && FLOW_NAV.some((item) => item.id === firstSegment)) {
    return { route: firstSegment, runId: "" };
  }
  return { route: "launch", runId: "" };
}

export function WorkbenchApp() {
  return (
    <ThemeProvider defaultPreference="light" defaultDensity="compact">
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

    if (command.mode === "approve") {
      setActive("policies");
      return;
    }
    if (command.mode === "verify") {
      setActive("evidence");
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      return;
    }
    if (command.mode === "replay") {
      setActive("evidence");
      if (receipts[0]) setDrawerItem({ kind: "receipt", receipt: receipts[0] });
      await runReplayProbe(receipts[0] ?? null);
      return;
    }
    if (command.mode === "inspect") {
      if (text.includes("sandbox")) {
        setActive("sandbox");
      } else if (text.includes("mcp")) {
        setActive("mcp");
      } else {
        setActive("registry");
      }
      return;
    }
    if (command.mode === "launch") {
      setActive("launch");
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
      setActive("evidence");
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Intent evaluation failed");
    } finally {
      setSubmitting(false);
    }
  }, [bootstrap?.workspace, commandText, principal, receipts, runReplayProbe, setReceipts, submitting]);

  const runQuickAction = useCallback((action: QuickAction) => {
    if (action.id === "evaluate-intent") {
      setActive("developer");
      setCommandText(action.command);
      composerRef.current?.focus();
      return;
    }
    if (action.id === "scan-mcp") {
      setActive("mcp");
      return;
    }
    if (action.id === "inspect-sandbox") {
      setActive("sandbox");
      return;
    }
    void submitCommand(action.command, "quick_action");
  }, [submitCommand]);

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
      setActive("receipts");
    }
  }, [receipts]);

  return (
    <HelmAiKernelAgentProvider enabled state={agentState}>
      <WorkbenchShell
        securityStance={receipts[0] ? normalizeVerdict(receipts[0].status) : "pending"}
        rail={<Navigation active={active} tasks={tasks} onNavigate={(route) => navigate(route)} />}
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
          <DetailDrawer
            item={drawerItem}
            fallbackReceipt={selectedReceipt}
            replayStatus={replayStatus}
            onClose={() => setDrawerItem(null)}
            onNavigate={navigate}
            onOpen={(item) => setDrawerItem(item)}
            onReplay={() => void runReplayProbe(selectedReceipt)}
            onRefresh={refreshOne}
          />
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
}: {
  readonly active: FlowRoute;
  readonly tasks: readonly OperatorTask[];
  readonly onNavigate: (route: FlowRoute) => void;
}) {
  const workCount = tasks.filter((task) => task.route === "work" || task.kind === "approval" || task.kind === "connector" || task.kind === "sandbox").length;
  const ledgerCount = tasks.filter((task) => task.route === "ledger").length;
  const counts: Partial<Record<FlowRoute, number>> = { work: workCount, ledger: ledgerCount };
  return (
    <WorkbenchRail brand="HELM" mark="H" onBrandClick={() => onNavigate("workbench")}>
      {FLOW_NAV.map((item) => (
        <WorkbenchRailLink
          key={item.id}
          active={active === item.id}
          label={item.label}
          count={counts[item.id]}
          icon={item.icon}
          onClick={() => onNavigate(item.id)}
        />
      ))}
    </WorkbenchRail>
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
        </>
      }
    />
  );
}

function WorkbenchFlow({
  snapshot,
  bootstrap,
  receipts,
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
  return (
    <div className="flow-page workbench-page">
      <WorkbenchComposer
        title="Governed agent cockpit"
        body="Start with one intent. HELM evaluates policy, records proof, and exposes approvals, replay, evidence, and runtime capabilities only when they matter."
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

      <WorkbenchQuickActions>
        {snapshot.quickActions.map((action) => (
          <WorkbenchQuickAction key={action.id} label={action.label} hint={action.hint} onClick={() => onQuickAction(action)} />
        ))}
      </WorkbenchQuickActions>

      <section className="health-strip" aria-label="Console health">
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

      <div className="workbench-grid">
        <section className="timeline-panel" aria-labelledby="timeline-title">
          <SectionHead title="Lifecycle" meta={snapshot.latestProof.label} />
          <Timeline steps={snapshot.activeTimeline} onOpen={(step) => onOpen({ kind: "timeline", step })} />
        </section>
        <section className="proof-panel" aria-labelledby="proof-title">
          <SectionHead title="Latest Proof" meta={snapshot.latestProof.state} />
          <div className="latest-proof">
            <FileSearch size={19} aria-hidden />
            <div>
              <strong>{snapshot.latestProof.action}</strong>
              <span>{snapshot.latestProof.resource}</span>
              <small>{snapshot.latestProof.label}</small>
            </div>
            {receipts[0] ? (
              <button type="button" onClick={() => onOpen({ kind: "receipt", receipt: receipts[0] })}>
                Inspect
              </button>
            ) : (
              <button type="button" onClick={() => onNavigate("ledger")}>
                Ledger
              </button>
            )}
          </div>
          <div className="proof-shortcuts">
            <button type="button" onClick={() => onNavigate("launch")}>Launch</button>
            <button type="button" onClick={() => onNavigate("runs")}>Runs</button>
            <button type="button" onClick={() => onNavigate("evidence")}>Evidence</button>
          </div>
        </section>
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

function DetailDrawer({
  item,
  fallbackReceipt,
  replayStatus,
  onClose,
  onNavigate,
  onOpen,
  onReplay,
  onRefresh,
}: {
  readonly item: DrawerItem | null;
  readonly fallbackReceipt: Receipt | null;
  readonly replayStatus: string;
  readonly onClose: () => void;
  readonly onNavigate: (route: FlowRoute, item?: DrawerItem) => void;
  readonly onOpen: (item: DrawerItem) => void;
  readonly onReplay: () => void;
  readonly onRefresh: (id: string) => Promise<void>;
}) {
  const visibleItem = item ?? (fallbackReceipt ? { kind: "receipt" as const, receipt: fallbackReceipt } : null);
  return (
    <WorkbenchDrawerFrame open={Boolean(item)} title="Context" onClose={onClose}>
      {!visibleItem ? (
        <EmptyLine title="No selection" body="Select work, proof, capability, or diagnostics to inspect details." />
      ) : visibleItem.kind === "task" ? (
        <TaskDetail task={visibleItem.task} onNavigate={onNavigate} />
      ) : visibleItem.kind === "receipt" ? (
        <ReceiptDetail receipt={visibleItem.receipt} replayStatus={replayStatus} onReplay={onReplay} />
      ) : visibleItem.kind === "capability" ? (
        <CapabilityDetail capability={visibleItem.capability} onOpen={onOpen} />
      ) : visibleItem.kind === "record" ? (
        <RecordDetail capability={visibleItem.capability} record={visibleItem.record} onOpen={onOpen} />
      ) : visibleItem.kind === "action" ? (
        <ActionSheet capability={visibleItem.capability} action={visibleItem.action} onRefresh={onRefresh} />
      ) : visibleItem.kind === "diagnostics" ? (
        <DiagnosticsDetail diagnostics={visibleItem.diagnostics} onNavigate={onNavigate} />
      ) : (
        <TimelineDetail step={visibleItem.step} />
      )}
    </WorkbenchDrawerFrame>
  );
}

function TaskDetail({ task, onNavigate }: { readonly task: OperatorTask; readonly onNavigate: (route: FlowRoute, item?: DrawerItem) => void }) {
  return (
    <div className="drawer-stack">
      <StateMarker state={task.state} severity={task.severity} />
      <h2>{task.title}</h2>
      <p>{task.summary}</p>
      <dl className="fact-grid">
        <Fact label="source" value={task.source} />
        <Fact label="state" value={task.state} />
        <Fact label="receipts" value={task.relatedReceiptIds.length ? task.relatedReceiptIds.map(shortId).join(", ") : "none"} />
      </dl>
      <button type="button" className="primary-action" onClick={() => onNavigate(task.route)}>
        {task.actionLabel}
      </button>
    </div>
  );
}

function ReceiptDetail({ receipt, replayStatus, onReplay }: { readonly receipt: Receipt; readonly replayStatus: string; readonly onReplay: () => void }) {
  return (
    <div className="drawer-stack">
      <div className="drawer-title-row">
        <VerdictBadge state={normalizeVerdict(receipt.status)} />
        <VerificationStatus state={verificationState(receipt)} />
      </div>
      <h2>{shortId(receipt.receipt_id)}</h2>
      <p>{receiptAction(receipt)} · {receiptResource(receipt)}</p>
      <WorkbenchProofSection title="Lifecycle">
        <div className="proof-chain" aria-label="Receipt proof chain">
          {["intent", "policy", "decision", "receipt", "evidence"].map((node) => (
            <span key={node}>{node}</span>
          ))}
        </div>
      </WorkbenchProofSection>
      <WorkbenchProofSection title="Proof facts">
        <dl className="fact-grid">
          <Fact label="executor" value={receipt.executor_id ?? "anonymous"} />
          <Fact label="signature" value={signatureSummary(receipt)} />
          <Fact label="blob hash" value={receipt.blob_hash ? <HashText value={receipt.blob_hash} /> : "not emitted"} />
          <Fact label="output hash" value={receipt.output_hash ? <HashText value={receipt.output_hash} kind="policy" /> : "not emitted"} />
          <Fact label="replay" value={replayStatus} />
        </dl>
      </WorkbenchProofSection>
      <div className="button-row">
        <button type="button" className="primary-action" onClick={onReplay}>Replay</button>
        <span className="secondary-link secondary-link--static">Evidence export: Ledger action</span>
      </div>
      <RawJson title="Raw receipt" value={receipt} />
    </div>
  );
}

function CapabilityDetail({ capability, onOpen }: { readonly capability: Capability; readonly onOpen: (item: DrawerItem) => void }) {
  return (
    <div className="drawer-stack">
      <StateMarker state={capability.status} severity={capability.status === "unavailable" || capability.status === "unauthorized" ? "medium" : "low"} />
      <h2>{capability.label}</h2>
      <p>{capability.sourceEndpoint}</p>
      {capability.readState.message ? <InlineNotice message={capability.readState.message} /> : null}
      <dl className="fact-grid">
        <Fact label="group" value={capability.group} />
        <Fact label="records" value={String(capability.records.length)} />
        <Fact label="actions" value={String(capability.actions.length)} />
      </dl>
      <div className="drawer-actions">
        {capability.actions.length === 0 ? <InlineNotice message={capability.unsupportedReason ?? "Unsupported by current OSS API."} /> : null}
        {capability.actions.map((action) => (
          <button
            key={action.id}
            type="button"
            disabled={Boolean(action.disabledReason)}
            title={action.disabledReason}
            onClick={() => onOpen({ kind: "action", capability, action })}
          >
            <span>{action.label}</span>
            <small>{action.method}</small>
          </button>
        ))}
      </div>
      {capability.id === "diagnostics" ? <RuntimeDiagnostics raw={capability.raw} /> : null}
      <RecordMiniList capability={capability} onOpen={onOpen} />
      <RawJson title="Raw response" value={capability.raw ?? capability.readState} />
    </div>
  );
}

function RuntimeDiagnostics({ raw }: { readonly raw: unknown }) {
  const stores = diagnosticsStores(raw);
  const routes = diagnosticsRoutes(raw);
  if (stores.length === 0 && routes.length === 0) return null;
  return (
    <>
      {stores.length ? (
        <WorkbenchProofSection title="Runtime stores">
          <WorkbenchStoreHealthList stores={stores} />
        </WorkbenchProofSection>
      ) : null}
      {routes.length ? (
        <WorkbenchProofSection title="Route coverage">
          <WorkbenchRouteCoverageTable routes={routes} />
        </WorkbenchProofSection>
      ) : null}
    </>
  );
}

function diagnosticsStores(raw: unknown) {
  if (!isRecord(raw) || !Array.isArray(raw.stores)) return [];
  return raw.stores.filter(isRecord).map((store, index) => ({
    id: stringValue(store.id, `store-${index}`),
    label: stringValue(store.label, stringValue(store.id, "Store")),
    status: stringValue(store.status, "unknown"),
    backend: stringValue(store.backend, "unknown"),
    source: optionalString(store.source),
    path: optionalString(store.path),
    detail: optionalString(store.detail),
  }));
}

function diagnosticsRoutes(raw: unknown) {
  if (!isRecord(raw) || !Array.isArray(raw.routes)) return [];
  return raw.routes.filter(isRecord).map((route) => ({
    method: stringValue(route.method, "GET"),
    path: stringValue(route.path, "/"),
    auth: stringValue(route.auth, "unknown"),
    contract_status: stringValue(route.contract_status, "unknown"),
    group: stringValue(route.group, "Developer"),
    ui_coverage: stringValue(route.ui_coverage, "missing"),
    unsupported_reason: optionalString(route.unsupported_reason),
  }));
}

function stringValue(value: unknown, fallback: string): string {
  const text = String(value ?? "").trim();
  return text || fallback;
}

function optionalString(value: unknown): string | undefined {
  const text = String(value ?? "").trim();
  return text || undefined;
}

function RecordDetail({ capability, record, onOpen }: { readonly capability: Capability; readonly record: RecordSummary; readonly onOpen: (item: DrawerItem) => void }) {
  return (
    <div className="drawer-stack">
      <StateMarker state={record.state} severity="low" />
      <h2>{record.label}</h2>
      <p>{record.source}</p>
      <dl className="fact-grid">
        <Fact label="state" value={record.state} />
        <Fact label="receipts" value={record.receiptRefs.length ? record.receiptRefs.map(shortId).join(", ") : "none"} />
        {record.facts.map((fact) => {
          const [label, ...rest] = fact.split(": ");
          return <Fact key={fact} label={label} value={rest.join(": ")} />;
        })}
      </dl>
      <div className="drawer-actions">
        {capability.actions.slice(0, 4).map((action) => (
          <button key={action.id} type="button" onClick={() => onOpen({ kind: "action", capability, action })}>
            <span>{action.label}</span>
            <small>{action.method}</small>
          </button>
        ))}
      </div>
      <RawJson title="Raw record" value={record.raw} />
    </div>
  );
}

function ActionSheet({ capability, action, onRefresh }: { readonly capability: Capability; readonly action: WorkbenchAction; readonly onRefresh: (id: string) => Promise<void> }) {
  const [values, setValues] = useState<AdminActionValues>(() => {
    const defaults: Record<string, string> = {};
    for (const field of action.fields) defaults[field.id] = field.defaultValue ?? "";
    return defaults;
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<unknown>(null);
  const [humanConfirmed, setHumanConfirmed] = useState(false);
  const sideEffectful = action.method.toUpperCase() !== "GET";
  const cliEquivalent = cliForAdminAction(action);
  const receiptRefs = result ? receiptRefsFromUnknown(result) : [];

  const runAction = async () => {
    if (sideEffectful && !humanConfirmed) {
      setError("A human operator confirmation is required before this side effect can run.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const next = await action.run(values);
      setResult(next);
      await Promise.all(action.refreshTargets.map((target) => onRefresh(target)));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="drawer-stack action-sheet"
      onSubmit={(event) => {
        event.preventDefault();
        void runAction();
      }}
    >
      <StateMarker state={action.method} severity="medium" />
      <WorkbenchActionSheetFrame title={action.label} method={action.method} endpoint={action.endpoint} risk={action.risk}>
        <p>{capability.label}</p>
        <section className="human-action-boundary" aria-label="Human-only action boundary">
          <strong>{sideEffectful ? "Human-only side effect" : "Read-only browser action"}</strong>
          <p>HELM AI can explain, draft, summarize, and simulate. HELM AI cannot approve, weaken, bypass, launch, inject secrets, or delete evidence.</p>
          <dl className="fact-grid">
            <Fact label="permission" value={`${action.method} ${action.endpoint}`} />
            <Fact label="CLI equivalent" value={cliEquivalent} />
            <Fact label="expected receipt" value={sideEffectful ? "required after successful mutation" : "not required for read-only inspection"} />
          </dl>
          {sideEffectful ? (
            <label className="human-confirm-check">
              <input type="checkbox" checked={humanConfirmed} onChange={(event) => setHumanConfirmed(event.target.checked)} />
              <span>I am the human operator authorizing this Console side effect.</span>
            </label>
          ) : null}
        </section>
        {action.disabledReason ? <InlineNotice message={action.disabledReason} /> : null}
        {action.fields.length === 0 ? <InlineNotice message="This action sends no request body fields." /> : null}
        {action.fields.map((field) => (
          <label key={field.id}>
            <span>{field.label}{field.required ? " *" : ""}</span>
            {field.kind === "textarea" ? (
              <textarea
                value={values[field.id] ?? ""}
                placeholder={field.placeholder}
                required={field.required}
                onChange={(event) => setValues((current) => ({ ...current, [field.id]: event.target.value }))}
              />
            ) : field.kind === "select" ? (
              <select
                value={values[field.id] ?? ""}
                required={field.required}
                onChange={(event) => setValues((current) => ({ ...current, [field.id]: event.target.value }))}
              >
                <option value="">Select...</option>
                {(field.options ?? []).map((option) => <option key={option} value={option}>{option}</option>)}
              </select>
            ) : (
              <input
                value={values[field.id] ?? ""}
                placeholder={field.placeholder}
                required={field.required}
                onChange={(event) => setValues((current) => ({ ...current, [field.id]: event.target.value }))}
              />
            )}
          </label>
        ))}
        {error ? <InlineError message={error} /> : null}
        <button type="submit" className="primary-action" disabled={busy || Boolean(action.disabledReason) || (sideEffectful && !humanConfirmed)}>
          {busy ? "Running" : `Run ${action.label}`}
        </button>
        {result ? (
          <>
            <dl className="fact-grid">
              <Fact label="receipt postcondition" value={receiptRefs.length ? receiptRefs.map(shortId).join(", ") : "unproven"} />
            </dl>
            <RawJson title="Action result" value={result} />
          </>
        ) : null}
      </WorkbenchActionSheetFrame>
    </form>
  );
}

function DiagnosticsDetail({ diagnostics, onNavigate }: { readonly diagnostics: readonly WorkbenchDiagnostic[]; readonly onNavigate: (route: FlowRoute) => void }) {
  return (
    <div className="drawer-stack">
      <StateMarker state={`${diagnostics.length} diagnostics`} severity={diagnostics.length ? "medium" : "low"} />
      <h2>Diagnostics</h2>
      <p>Fail-closed API states are condensed here so the workbench stays focused.</p>
      {diagnostics.length === 0 ? <EmptyLine title="No diagnostics" body="No unavailable protected route is currently visible." /> : null}
      <div className="record-list">
        {diagnostics.map((item) => (
          <WorkbenchRecordRow key={item.id} title={item.label} detail={item.message} meta={item.source} onClick={() => onNavigate(item.route)} />
        ))}
      </div>
    </div>
  );
}

function TimelineDetail({ step }: { readonly step: TaskTimelineStep }) {
  return (
    <div className="drawer-stack">
      <StateMarker state={step.state} severity={step.state === "failed" || step.state === "blocked" ? "high" : step.state === "running" ? "medium" : "low"} />
      <h2>{step.label}</h2>
      <p>{step.summary}</p>
      <dl className="fact-grid">
        <Fact label="source" value={step.sourceEndpoint ?? "frontend view model"} />
        <Fact label="receipts" value={step.receiptRefs.length ? step.receiptRefs.map(shortId).join(", ") : "none"} />
        <Fact label="artifacts" value={step.artifactRefs.length ? step.artifactRefs.map(shortId).join(", ") : "none"} />
      </dl>
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
