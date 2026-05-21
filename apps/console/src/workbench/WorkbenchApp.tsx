"use client";

import {
  AlertCircle,
  CheckCircle2,
  ChevronRight,
  Circle,
  FileSearch,
  MessageSquareText,
} from "lucide-react";
import { useState, type ComponentType, type ReactNode } from "react";
import {
  ErrorBoundary,
  I18nProvider,
  TelemetryProvider,
  ThemeProvider,
  Button,
  FormField,
  SelectField,
  TextInput,
  WorkbenchCommandSearch,
  WorkbenchHealthSummary,
  WorkbenchHeader,
  WorkbenchIntegrationCard,
  WorkbenchRecordRow,
  WorkbenchSectionHeader,
  WorkbenchShell,
  WorkbenchStatusFact,
  WorkbenchTimelineStep,
} from "@mindburn/ui-core";
import {
  getConsoleTenantID,
  hasConsoleAdminKey,
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
import { LaunchpadPage } from "../features/launchpad/LaunchpadPage";
import { useWorkbenchState } from "./hooks/useWorkbenchState";
import { Navigation, MobileNav } from "./components/SideRailNavigation";
import { UniversalComposer } from "./components/UniversalComposer";
import { DetailDrawer } from "./components/HELMInspector";
import {
  normalizeState,
  receiptAction,
  receiptKey,
  receiptResource,
  shortId,
} from "./viewModels";
import type {
  Capability,
  CapabilityGroup,
  FlowRoute,
  OperatorTask,
  QuickAction,
  TaskSeverity,
  TaskTimelineStep,
  WorkbenchSnapshot,
  DrawerItem,
  SearchResult,
} from "./types";
import type { ConsoleAccessState } from "./dataHooks";

const ConsoleBoundary = ErrorBoundary as unknown as ComponentType<{ readonly children: ReactNode }>;

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

function routeLabel(route: FlowRoute): string {
  switch (route) {
    case "launch":
      return "Launch";
    case "runs":
      return "Runs";
    case "mcp":
      return "MCP Firewall";
    case "policies":
      return "Policies";
    case "secrets":
      return "Secrets";
    case "sandbox":
      return "Sandbox";
    case "evidence":
      return "Evidence";
    case "receipts":
      return "Receipts";
    case "registry":
      return "Registry";
    case "settings":
      return "Settings";
    default:
      return "Workbench";
  }
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
  const {
    initialRoute,
    bootstrap,
    receipts,
    streamState,
    accessState,
    refreshing,
    refresh,
    active,
    capabilities,
    capabilitiesLoading,
    refreshOne,
    refreshAll,
    query,
    setQuery,
    drawerItem,
    setDrawerItem,
    commandText,
    setCommandText,
    principal,
    setPrincipal,
    submitting,
    actionError,
    replayStatus,
    assistantOpen,
    setAssistantOpen,
    composerRef,
    authChanged,
    selectedReceipt,
    tasks,
    snapshot,
    agentState,
    filteredReceipts,
    searchResults,
    navigate,
    runReplayProbe,
    submitCommand,
    runQuickAction,
    openSearchResult,
    navigateFromAssistant,
    selectReceiptFromAssistant,
  } = useWorkbenchState();

  return (
    <HelmAiKernelAgentProvider enabled state={agentState}>
      <WorkbenchShell
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
          <StatusPill
            label="access"
            value={accessState === "authorized" ? "ready" : accessState}
            tone={accessState === "authorized" ? "good" : "warn"}
          />
          <StatusPill
            label="stream"
            value={streamState}
            tone={streamState === "live" ? "good" : "warn"}
          />
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
      <UniversalComposer
        snapshot={snapshot}
        commandText={commandText}
        principal={principal}
        submitting={submitting}
        actionError={actionError}
        refreshing={refreshing}
        composerRef={composerRef}
        onCommandChange={onCommandChange}
        onPrincipalChange={onPrincipalChange}
        onSubmit={onSubmit}
        onQuickAction={onQuickAction}
        onRefresh={onRefresh}
      />

      <section className="health-strip" aria-label="Console health">
        <WorkbenchHealthSummary
          state={snapshot.healthSummary.state}
          label={snapshot.healthSummary.label}
          message={snapshot.healthSummary.message}
          action={
            snapshot.diagnostics.length > 0 ? (
              <Button
                variant="secondary"
                onClick={() => onOpen({ kind: "diagnostics", diagnostics: snapshot.diagnostics })}
              >
                Open diagnostics
              </Button>
            ) : null
          }
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
  const workTasks = tasks.filter(
    (task) =>
      task.route === "work" ||
      task.kind === "approval" ||
      task.kind === "connector" ||
      task.kind === "sandbox"
  );
  const workCapabilities = capabilities.filter((capability) => WORK_CAPABILITY_IDS.has(capability.id));
  return (
    <div className="flow-page">
      <FlowHeader
        title="Work"
        body="Approvals, escalations, MCP quarantine, sandbox grants, authz checks, and budget ceilings that require operator attention."
      />
      <section className="list-section">
        <SectionHead
          title="Actionable Work"
          meta={`${workTasks.length} task${workTasks.length === 1 ? "" : "s"}`}
        />
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
    if (filter === "verified") {
      const explicitState = receipt.metadata?.verification_status ?? receipt.metadata?.verification_state;
      return String(explicitState ?? "").toLowerCase() === "pass" || String(explicitState ?? "").toLowerCase() === "passed" || String(explicitState ?? "").toLowerCase() === "verified";
    }
    if (filter === "failed") {
      const explicitState = receipt.metadata?.verification_status ?? receipt.metadata?.verification_state;
      return String(explicitState ?? "").toLowerCase() === "fail" || String(explicitState ?? "").toLowerCase() === "failed" || normalizeState(receipt.status).includes("fail");
    }
    return normalizeState(receipt.status).includes(filter);
  });
  return (
    <div className="flow-page">
      <FlowHeader
        title="Ledger"
        body="Receipts, replay, evidence export, conformance reports, vectors, and negative gates."
        action={
          <button
            type="button"
            className="secondary-action"
            disabled={refreshing}
            onClick={onRefresh}
          >
            {refreshing ? "Refreshing" : "Refresh receipts"}
          </button>
        }
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
    const queryMatch =
      !term ||
      `${capability.label} ${capability.group} ${capability.sourceEndpoint}`
        .toLowerCase()
        .includes(term);
    return groupMatch && queryMatch;
  });
  return (
    <div className="flow-page">
      <FlowHeader
        title="Capabilities"
        body="A simple directory for MCP, sandbox, authz, budgets, boundary, telemetry, coexistence, and developer contracts."
        action={
          <button
            type="button"
            className="secondary-action"
            disabled={loading}
            onClick={onRefreshAll}
          >
            {loading ? "Loading" : "Refresh all"}
          </button>
        }
      />
      <Segmented
        value={group}
        options={CAPABILITY_GROUPS}
        onChange={(value) => setGroup(value as "All" | CapabilityGroup)}
      />
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
        <button
          type="button"
          className="secondary-action"
          disabled={busy !== null}
          onClick={() => void runDemoScenario()}
        >
          {busy === "run" ? "Running" : "Run sample"}
        </button>
        <button
          type="button"
          className="secondary-action"
          disabled={!demoResult || busy !== null}
          onClick={() => void verifyDemoScenario()}
        >
          Verify
        </button>
        <button
          type="button"
          className="secondary-action"
          disabled={!demoResult || busy !== null}
          onClick={() => void tamperDemoScenario()}
        >
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
  readonly surface:
    | "launch"
    | "apps"
    | "runs"
    | "policies"
    | "mcp"
    | "secrets"
    | "evidence"
    | "sandbox"
    | "receipts"
    | "registry";
  readonly initialRunId?: string;
}) {
  const titles = {
    launch: [
      "Launch",
      "Default proof workbench: choose any AppSpec, compile gates, and inspect the run timeline.",
    ],
    apps: [
      "Launch",
      "Select any agentic app and launch only through HELM's fail-closed execution boundary.",
    ],
    runs: [
      "Runs",
      "Receipt-backed runtime instances, launch decisions, healthchecks, EvidencePacks, and teardown.",
    ],
    policies: [
      "Policies",
      "Policy workbench with plain English, structured grants, and raw canonical references.",
    ],
    mcp: [
      "MCP Firewall",
      "Quarantined MCP servers and tools stay blocked until receipt-backed approval.",
    ],
    secrets: [
      "Secrets",
      "Secret grants show presence, scope, grant hash, and launch impact without raw values.",
    ],
    evidence: [
      "Evidence",
      "EvidencePacks, offline verification commands, and proof status for local verification.",
    ],
    sandbox: [
      "Sandbox",
      "Runtime filesystem, env, network, resources, and grant hash as execution-boundary truth.",
    ],
    receipts: ["Receipts", "Signed receipt refs for run state. Missing receipt means unproven."],
    registry: [
      "Registry",
      "Raw registry, substrates, and compatibility matrix that drive every Console screen.",
    ],
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
      <FlowHeader
        title="Settings"
        body="Session credentials, tenant routing, runtime health, and protected API recovery."
      />
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
            <button type="submit" className="primary-action" disabled={adminKey.trim() === ""}>
              Use key
            </button>
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
          <button type="submit" className="primary-action">
            Save tenant
          </button>
        </form>
      </section>
      <section className="list-section">
        <SectionHead title="Runtime Health" meta={streamState} />
        <div className="health-strip">
          <StatusPill label="workspace" value={bootstrap?.workspace.project ?? "pending"} />
          <StatusPill label="environment" value={bootstrap?.workspace.environment ?? "pending"} />
          <StatusPill label="kernel" value={bootstrap?.health.kernel ?? "pending"} />
          <StatusPill label="policy" value={bootstrap?.health.policy ?? "pending"} />
          <StatusPill
            label="diagnostics"
            value={String(snapshot.diagnostics.length)}
            tone={snapshot.diagnostics.length ? "warn" : "good"}
          />
          <button type="button" className="secondary-action" onClick={onOpenDiagnostics}>
            Open diagnostics
          </button>
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
  if (tasks.length === 0) {
    return (
      <EmptyLine
        title="No operator work"
        body="Approvals, quarantines, denied receipts, and blocked grants will appear here from live API state."
      />
    );
  }
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
          <button
            type="button"
            className="row-action"
            onClick={() => onNavigate(task.route, { kind: "task", task })}
          >
            {task.actionLabel}
          </button>
        </article>
      ))}
    </div>
  );
}

function CapabilityRows({
  capabilities,
  onOpen,
}: {
  readonly capabilities: readonly Capability[];
  readonly onOpen: (item: DrawerItem) => void;
}) {
  if (capabilities.length === 0) {
    return (
      <EmptyLine
        title="No capabilities"
        body="No matching API-backed capability is currently registered."
      />
    );
  }
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

function ReceiptRows({
  receipts,
  onOpen,
}: {
  readonly receipts: readonly Receipt[];
  readonly onOpen: (receipt: Receipt) => void;
}) {
  if (receipts.length === 0) {
    return (
      <EmptyLine
        title="No receipts"
        body="Evaluate a governed intent or connect a runtime to start the ledger."
      />
    );
  }
  return (
    <div className="receipt-list">
      {receipts.map((receipt) => (
        <button
          key={receiptKey(receipt)}
          type="button"
          className="receipt-row"
          onClick={() => onOpen(receipt)}
        >
          <span className={`receipt-state state-${normalizeState(receipt.status, "pending")}`} />
          <strong>{receiptAction(receipt)}</strong>
          <span>{receiptResource(receipt)}</span>
          <em>{shortId(receipt.receipt_id)}</em>
        </button>
      ))}
    </div>
  );
}

function Timeline({
  steps,
  onOpen,
}: {
  readonly steps: readonly TaskTimelineStep[];
  readonly onOpen: (step: TaskTimelineStep) => void;
}) {
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

function FlowHeader({
  title,
  body,
  action,
}: {
  readonly title: string;
  readonly body: string;
  readonly action?: ReactNode;
}) {
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
        <button
          key={option}
          type="button"
          role="tab"
          aria-selected={option === value}
          className={option === value ? "is-active" : ""}
          onClick={() => onChange(option)}
        >
          {option}
        </button>
      ))}
    </div>
  );
}

function StatusPill({
  label,
  value,
  tone = "neutral",
}: {
  readonly label: string;
  readonly value: string;
  readonly tone?: "neutral" | "good" | "warn";
}) {
  return <WorkbenchStatusFact label={label} value={value} tone={tone} />;
}

function StateMarker({
  state,
  severity,
}: {
  readonly state: string;
  readonly severity: TaskSeverity;
}) {
  return (
    <span className={`state-marker severity-${severity}`}>
      <Circle size={8} aria-hidden />
      {state}
    </span>
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
