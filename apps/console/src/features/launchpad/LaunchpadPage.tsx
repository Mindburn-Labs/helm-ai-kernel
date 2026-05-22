import { AlertTriangle, CheckCircle2, Clipboard, Download, Loader2, Play, RefreshCw, Trash2, Shield, ShieldCheck, ShieldAlert, Key, Globe, FolderOpen, FileText, Check, ArrowRight, ArrowLeft, Lock, Unlock, Cpu } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { launchpadApi } from "./api";
import { AppCard } from "./AppCard";
import { ProofPanel } from "./ProofPanel";
import { RunTimeline } from "./RunTimeline";
import { SimpleLaunchHome } from "./SimpleLaunchHome";
import { CanvasElement, VisualCodeDiff, AnnotatedCodeBlock, type CodeAnnotation } from "@mindburn/ui-core";
import type {
  FixAction,
  GateResult,
  LaunchpadApp,
  LaunchpadMatrixCell,
  LaunchpadPlanResponse,
  LaunchpadRun,
  LaunchpadRunDetail,
  LaunchpadSecretGrant,
  LaunchpadSubstrate,
  MCPThreatReview,
  PolicySimulation,
  RunEvent,
  SandboxGrantView,
} from "./types";

type LaunchpadSurface = "launch" | "apps" | "runs" | "policies" | "mcp" | "secrets" | "evidence" | "sandbox" | "receipts" | "registry";
type InspectorItem = { kind: "event"; value: RunEvent } | { kind: "gate"; value: GateResult } | null;
type Notice = { tone: "success" | "error" | "info"; message: string } | null;
type SecretRequirement = { logical: string; env: string; present: boolean; cli: string; grant?: LaunchpadSecretGrant };

export function LaunchpadPage({ surface = "launch", initialRunId = "" }: { readonly surface?: LaunchpadSurface; readonly initialRunId?: string }) {
  const [viewMode, setViewMode] = useState<"simple" | "pro">(() => {
    const stored = localStorage.getItem("helm-console-viewmode");
    return stored === "pro" ? "pro" : "simple";
  });
  const [apps, setApps] = useState<LaunchpadApp[]>([]);
  const [substrates, setSubstrates] = useState<LaunchpadSubstrate[]>([]);
  const [matrix, setMatrix] = useState<LaunchpadMatrixCell[]>([]);
  const [runs, setRuns] = useState<LaunchpadRun[]>([]);
  const [secrets, setSecrets] = useState<LaunchpadSecretGrant[]>([]);
  const [threatReviews, setThreatReviews] = useState<MCPThreatReview[]>([]);
  const [selectedApp, setSelectedApp] = useState("");
  const [selectedSubstrate, setSelectedSubstrate] = useState("");
  const [plan, setPlan] = useState<LaunchpadPlanResponse | null>(null);
  const [policySimulation, setPolicySimulation] = useState<PolicySimulation | null>(null);
  const [detail, setDetail] = useState<LaunchpadRunDetail | null>(null);
  const [sandboxGrant, setSandboxGrant] = useState<SandboxGrantView | null>(null);
  const [receipts, setReceipts] = useState<string[]>([]);
  const [, setRunLog] = useState("");
  const [inspector, setInspector] = useState<InspectorItem>(null);
  const [notice, setNotice] = useState<Notice>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    setNotice(null);
    const issues: string[] = [];
    const loadPiece = async <T,>(label: string, read: () => Promise<T>, apply: (value: T) => void) => {
      try {
        apply(await read());
      } catch (err) {
        issues.push(`${label}: ${err instanceof Error ? err.message : "unavailable"}`);
      }
    };
    await Promise.all([
      loadPiece("apps", launchpadApi.apps, (nextApps) => {
        setApps(nextApps);
        setSelectedApp((current) => current || nextApps[0]?.app_id || nextApps[0]?.id || "");
      }),
      loadPiece("substrates", launchpadApi.substrates, (nextSubstrates) => {
        setSubstrates(nextSubstrates);
        setSelectedSubstrate((current) => current || nextSubstrates.find((item) => item.id === "local-container")?.id || nextSubstrates[0]?.id || "");
      }),
      loadPiece("matrix", launchpadApi.matrix, setMatrix),
      loadPiece("runs", launchpadApi.runs, setRuns),
      loadPiece("secrets", launchpadApi.secrets, setSecrets),
      loadPiece("MCP reviews", launchpadApi.mcpThreatReviews, setThreatReviews),
    ]);
    if (issues.length > 0) {
      setNotice({ tone: "error", message: `Launchpad API unavailable. No fallback demo data was invented. ${issues.join("; ")}` });
    }
    setLoading(false);
  };

  useEffect(() => {
    void load();
  }, []);

  const app = useMemo(() => apps.find((item) => (item.app_id ?? item.id) === selectedApp), [apps, selectedApp]);
  const currentRunId = detail?.instance.run_id ?? detail?.run.launch_id ?? "";
  const canAct = !busy && !loading && Boolean(selectedApp) && Boolean(selectedSubstrate);

  const openRun = async (runId: string) => {
    if (!runId) return;
    setBusy(true);
    setNotice(null);
    try {
      const nextDetail = await launchpadApi.detail(runId);
      setDetail(nextDetail);
      setInspector(nextDetail.events[0] ? { kind: "event", value: nextDetail.events[0] } : nextDetail.gates[0] ? { kind: "gate", value: nextDetail.gates[0] } : null);
      setNotice({ tone: "info", message: `Opened run ${runId}.` });
      await loadRunDrilldowns(runId);
    } catch (err) {
      setNotice({ tone: "error", message: err instanceof Error ? err.message : "Run detail failed" });
    } finally {
      setBusy(false);
    }
  };

  const loadRunDrilldowns = async (runId: string) => {
    const [receiptBody, logBody, sandboxBody] = await Promise.all([
      launchpadApi.receipts(runId),
      launchpadApi.logs(runId),
      launchpadApi.sandbox(runId),
    ]);
    setReceipts(receiptBody.receipts ?? []);
    setRunLog(logBody.log ?? "");
    setSandboxGrant(sandboxBody.sandbox_grant ?? null);
  };

  useEffect(() => {
    if (!initialRunId || currentRunId === initialRunId) return;
    void openRun(initialRunId);
  }, [initialRunId, currentRunId]);

  const runPreflight = async (targetApp = selectedApp) => {
    if (!targetApp || !selectedSubstrate) return;
    setBusy(true);
    setNotice(null);
    try {
      const nextPlan = await launchpadApi.plan(targetApp, selectedSubstrate);
      setPlan(nextPlan);
      setNotice({ tone: "info", message: `${nextPlan.kernel_verdict}: LaunchPlan ${nextPlan.plan_hash ?? "unproven"} compiled.` });
    } catch (err) {
      setNotice({ tone: "error", message: err instanceof Error ? err.message : "Preflight failed" });
    } finally {
      setBusy(false);
    }
  };

  const createRun = async (targetApp = selectedApp) => {
    if (!targetApp || !selectedSubstrate) return;
    setBusy(true);
    setNotice(null);
    try {
      const nextDetail = await launchpadApi.run(targetApp, selectedSubstrate);
      setDetail(nextDetail);
      setSandboxGrant(nextDetail.instance.sandbox_grant ?? null);
      setReceipts(nextDetail.instance.receipts ?? []);
      setInspector(nextDetail.events[0] ? { kind: "event", value: nextDetail.events[0] } : nextDetail.gates[0] ? { kind: "gate", value: nextDetail.gates[0] } : null);
      setNotice({ tone: nextDetail.instance.verdict === "ALLOW" ? "success" : "info", message: `${nextDetail.instance.verdict}: run ${nextDetail.instance.run_id} is ${nextDetail.instance.state}.` });
      await load();
    } catch (err) {
      setNotice({ tone: "error", message: err instanceof Error ? err.message : "Launch failed" });
    } finally {
      setBusy(false);
    }
  };

  const simulatePolicy = async () => {
    if (!selectedApp || !selectedSubstrate) return;
    setBusy(true);
    setNotice(null);
    try {
      const simulation = await launchpadApi.simulatePolicy(selectedApp, selectedSubstrate);
      setPolicySimulation(simulation);
      setNotice({ tone: "info", message: `${simulation.verdict}: policy simulation completed for ${simulation.app_id}.` });
    } catch (err) {
      setNotice({ tone: "error", message: err instanceof Error ? err.message : "Policy simulation failed" });
    } finally {
      setBusy(false);
    }
  };

  const exportEvidence = async () => {
    if (!currentRunId) return;
    setBusy(true);
    setNotice(null);
    try {
      const exported = await launchpadApi.exportEvidence(currentRunId);
      setNotice({ tone: "success", message: `EvidencePack export ready: ${exported.evidencepack_ref ?? "unproven"}.` });
    } catch (err) {
      setNotice({ tone: "error", message: err instanceof Error ? err.message : "Evidence export failed" });
    } finally {
      setBusy(false);
    }
  };

  const bindSecret = async (requirement: SecretRequirement) => {
    setBusy(true);
    setNotice(null);
    try {
      await launchpadApi.bindSecret({ name: requirement.logical, provider: "env", value_env: requirement.env });
      setNotice({ tone: "success", message: `Secret grant binding requested for ${requirement.logical} from ${requirement.env}.` });
      await load();
    } catch (err) {
      setNotice({ tone: "error", message: err instanceof Error ? err.message : "Secret grant binding failed" });
    } finally {
      setBusy(false);
    }
  };

  const approveMcpReview = async (review: MCPThreatReview) => {
    setBusy(true);
    setNotice(null);
    try {
      const readOnlyTools = review.tools.filter((tool) => isReadOnlyTool(tool.side_effect_class)).map((tool) => tool.name);
      await launchpadApi.approveMcp({
        server_id: review.server_id,
        tools: readOnlyTools,
        ttl: "1h",
        reason: "human-scoped read-only Console approval",
        approver: "console-human-operator",
      });
      setNotice({ tone: "success", message: `Scoped approval receipt requested for ${review.server_id}.` });
      await load();
    } catch (err) {
      setNotice({ tone: "error", message: err instanceof Error ? err.message : "MCP approval failed" });
    } finally {
      setBusy(false);
    }
  };

  const teardown = async () => {
    if (!currentRunId) return;
    setBusy(true);
    setNotice(null);
    try {
      const nextDetail = await launchpadApi.teardown(currentRunId);
      setDetail(nextDetail);
      setInspector(nextDetail.events.at(-1) ? { kind: "event", value: nextDetail.events.at(-1)! } : null);
      setNotice({ tone: "success", message: `Teardown receipt emitted for ${currentRunId}.` });
      await load();
    } catch (err) {
      setNotice({ tone: "error", message: err instanceof Error ? err.message : "Teardown failed" });
    } finally {
      setBusy(false);
    }
  };

  const applyFix = async (cli: string) => {
    if (!currentRunId) return;
    setBusy(true);
    setNotice(null);
    try {
      await launchpadApi.repair(currentRunId);
      setNotice({ tone: "success", message: `Successfully executed fix: ${cli}` });
      await openRun(currentRunId);
      await load();
    } catch (err) {
      setNotice({ tone: "error", message: err instanceof Error ? err.message : "Repair action failed" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="launchpad-surface" aria-busy={loading || busy}>
      <div className="view-mode-switcher-container">
        <div className="view-mode-switcher" role="radiogroup" aria-label="Dashboard presentation depth">
          <button
            type="button"
            className={`view-mode-btn ${viewMode === "simple" ? "active" : ""}`}
            onClick={() => {
              setViewMode("simple");
              localStorage.setItem("helm-console-viewmode", "simple");
            }}
          >
            Simple
          </button>
          <button
            type="button"
            className={`view-mode-btn ${viewMode === "pro" ? "active" : ""}`}
            onClick={() => {
              setViewMode("pro");
              localStorage.setItem("helm-console-viewmode", "pro");
            }}
          >
            Developer
          </button>
        </div>
      </div>

      <section className="launchpad-panel launchpad-hero">
        <PanelHeader
          kicker={viewMode === "simple" ? "HELM Shield" : "HELM Console"}
          title={viewMode === "simple" ? "Deploy & Run Safely" : "Launch / Run Timeline"}
          description={
            viewMode === "simple"
              ? "Select an AppSpec and run backend preflight before any Launchpad runtime starts."
              : "Universal execution boundary: AppSpec -> Preflight -> LaunchPlan -> policy -> grants -> MCP quarantine -> runtime -> receipts -> EvidencePack -> offline verify."
          }
        />
        <button className="launchpad-action" type="button" disabled={loading || busy} onClick={() => void load()}>
          {loading ? <Loader2 className="spin" size={14} aria-hidden="true" /> : <RefreshCw size={14} aria-hidden="true" />}
          Refresh
        </button>
      </section>

      <section className="launchpad-status-panel" aria-live="polite">
        <PanelHeader
          kicker="Truth Source"
          title={loading ? "Loading backend state" : busy ? "Action running" : "Receipt-backed state"}
          description={notice?.tone === "error" ? "Launchpad API unavailable. No fallback demo data was invented." : notice?.message ?? "The UI renders backend facts only; missing proof is shown as unproven."}
        />
        <div className="launchpad-metrics" aria-label="HELM Console counts">
          <span><strong>{apps.length}</strong> apps</span>
          <span><strong>{runs.length}</strong> runs</span>
          {viewMode === "pro" && <span><strong>{threatReviews.length}</strong> MCP reviews</span>}
        </div>
      </section>

      {notice?.tone === "error" ? (
        <div className="inline-error" role="alert">
          <AlertTriangle size={14} /> {notice.message}
        </div>
      ) : null}

      {surface === "launch" || surface === "apps" ? (
        <LaunchSurface
          viewMode={viewMode}
          setViewMode={setViewMode}
          apps={apps}
          matrix={matrix}
          secrets={secrets}
          threatReviews={threatReviews}
          plan={plan}
          detail={detail}
          selectedApp={selectedApp}
          selectedSubstrate={selectedSubstrate}
          substrates={substrates}
          busy={!canAct}
          onSelectApp={setSelectedApp}
          onSelectSubstrate={setSelectedSubstrate}
          onPreflight={(appId) => void runPreflight(appId)}
          onLaunch={(appId) => void createRun(appId)}
          onBindSecret={(requirement) => void bindSecret(requirement)}
        />
      ) : null}

      {surface === "runs" ? <RunsSurface viewMode={viewMode} setViewMode={setViewMode} runs={runs} detail={detail} busy={busy} onOpenRun={(id) => void openRun(id)} onTeardown={() => void teardown()} onExportEvidence={() => void exportEvidence()} /> : null}
      {surface === "policies" ? <PolicySurface viewMode={viewMode} setViewMode={setViewMode} app={app} simulation={policySimulation} plan={plan} busy={busy} onSimulate={() => void simulatePolicy()} /> : null}
      {surface === "mcp" ? <McpSurface viewMode={viewMode} reviews={threatReviews} busy={busy} onApprove={(review) => void approveMcpReview(review)} /> : null}
      {surface === "secrets" ? <SecretsSurface viewMode={viewMode} secrets={secrets} apps={apps} busy={busy} onBindSecret={(requirement) => void bindSecret(requirement)} /> : null}
      {surface === "evidence" ? <EvidenceSurface viewMode={viewMode} runs={runs} detail={detail} onExport={() => void exportEvidence()} /> : null}
      {surface === "sandbox" ? <SandboxSurface viewMode={viewMode} grant={sandboxGrant ?? detail?.instance.sandbox_grant ?? null} detail={detail} /> : null}
      {surface === "receipts" ? <ReceiptsSurface viewMode={viewMode} receipts={receipts.length ? receipts : detail?.instance.receipts ?? []} detail={detail} /> : null}
      {surface === "registry" ? <RegistrySurface apps={apps} substrates={substrates} matrix={matrix} /> : null}

      <RunDetail
        viewMode={viewMode}
        setViewMode={setViewMode}
        detail={detail}
        inspector={inspector}
        onInspect={setInspector}
        onTeardown={() => void teardown()}
        onExport={() => void exportEvidence()}
        onApplyFix={applyFix}
      />
    </div>
  );
}

function PanelHeader({ kicker, title, description }: { readonly kicker: string; readonly title: string; readonly description?: string }) {
  return (
    <div className="panel-header">
      <span>{kicker}</span>
      <h2>{title}</h2>
      {description ? <p>{description}</p> : null}
    </div>
  );
}

function LaunchSurface({
  viewMode,
  setViewMode,
  apps,
  matrix,
  secrets,
  threatReviews,
  plan,
  detail,
  substrates,
  selectedApp,
  selectedSubstrate,
  busy,
  onSelectApp,
  onSelectSubstrate,
  onPreflight,
  onLaunch,
  onBindSecret,
}: {
  readonly viewMode: "simple" | "pro";
  readonly setViewMode: (mode: "simple" | "pro") => void;
  readonly apps: readonly LaunchpadApp[];
  readonly matrix: readonly LaunchpadMatrixCell[];
  readonly secrets: readonly LaunchpadSecretGrant[];
  readonly threatReviews: readonly MCPThreatReview[];
  readonly plan: LaunchpadPlanResponse | null;
  readonly detail: LaunchpadRunDetail | null;
  readonly substrates: readonly LaunchpadSubstrate[];
  readonly selectedApp: string;
  readonly selectedSubstrate: string;
  readonly busy: boolean;
  readonly onSelectApp: (id: string) => void;
  readonly onSelectSubstrate: (id: string) => void;
  readonly onPreflight: (id: string) => void;
  readonly onLaunch: (id: string) => void;
  readonly onBindSecret: (requirement: SecretRequirement) => void;
}) {
  if (viewMode === "simple") {
    return (
      <SimpleLaunchHome
        apps={apps}
        substrates={substrates}
        matrix={matrix}
        secrets={secrets}
        threatReviews={threatReviews}
        selectedApp={selectedApp}
        selectedSubstrate={selectedSubstrate}
        plan={plan}
        detail={detail}
        busy={busy}
        onSelectApp={onSelectApp}
        onSelectSubstrate={onSelectSubstrate}
        onPreflight={onPreflight}
        onLaunch={onLaunch}
        onBindSecret={onBindSecret}
      />
    );
  }

  return (
    <>
      <section className="launchpad-panel launch-toolbar">
        <PanelHeader kicker="Entry Point" title="Universal AppSpec launch" description="Launch compiles preflight gates first. Runtime starts only after mandatory gates resolve ALLOW." />
        <label className="launchpad-field">
          <span>Substrate</span>
          <select value={selectedSubstrate} disabled={busy || substrates.length === 0} onChange={(event) => onSelectSubstrate(event.target.value)}>
            {substrates.map((item) => <option key={item.id} value={item.id}>{item.name} - {item.availability}</option>)}
          </select>
        </label>
      </section>
      <section className="appspec-grid" aria-label="Registry applications">
        {apps.map((item) => {
          const appId = item.app_id ?? item.id;
          const cell = matrix.find((entry) => entry.app_id === appId && entry.substrate_id === selectedSubstrate);
          const appReviews = threatReviews.filter((review) => review.app_id === appId);
          return (
            <AppCard
              key={appId}
              app={item}
              selected={selectedApp === appId}
              substrate={substrates.find((substrate) => substrate.id === selectedSubstrate)}
              cell={cell}
              secrets={secrets}
              reviews={appReviews}
              busy={busy}
              onSelect={onSelectApp}
              onPreflight={onPreflight}
              onLaunch={onLaunch}
              onBindSecret={onBindSecret}
            />
          );
        })}
      </section>
    </>
  );
}

function RunsSurface({
  viewMode,
  setViewMode,
  runs,
  detail,
  busy,
  onOpenRun,
  onTeardown,
  onExportEvidence,
}: {
  readonly viewMode: "simple" | "pro";
  readonly setViewMode: (mode: "simple" | "pro") => void;
  readonly runs: readonly LaunchpadRun[];
  readonly detail: LaunchpadRunDetail | null;
  readonly busy: boolean;
  readonly onOpenRun: (id: string) => void;
  readonly onTeardown: () => void;
  readonly onExportEvidence?: () => void;
}) {
  const runId = detail?.instance.run_id ?? detail?.run.launch_id ?? "<run_id>";

  if (viewMode === "simple") {
    return (
      <RunTimeline
        runs={runs}
        detail={detail}
        busy={busy}
        onOpenRun={onOpenRun}
        onTeardown={onTeardown}
        onExportEvidence={onExportEvidence}
      />
    );
  }

  return (
    <section className="launchpad-panel">
      <div className="panel-head">
        <PanelHeader kicker="Runs" title="Runtime instances" description="Open a run to inspect its receipt-backed timeline." />
        <HumanOnlyActionButton
          label="Teardown"
          icon={<Trash2 size={14} aria-hidden="true" />}
          cli={`helm teardown ${runId} --cascade`}
          disabled={busy || !detail}
          disabledReason={!detail ? "Open a run before teardown." : undefined}
          destructive
          onConfirm={onTeardown}
        />
      </div>
      <div className="run-list">
        {runs.map((run) => (
          <button key={run.launch_id ?? run.id} type="button" onClick={() => onOpenRun(run.launch_id ?? run.id ?? "")}>
            <strong>{run.app_id}</strong>
            <span>{run.state}</span>
            <em>{run.kernel_verdict}</em>
            <code>{run.plan_hash ?? "unproven"}</code>
          </button>
        ))}
      </div>
      {runs.length === 0 ? <div className="launchpad-empty">No runtime instances yet.</div> : null}
    </section>
  );
}

function RunDetail({
  viewMode,
  setViewMode,
  detail,
  inspector,
  onInspect,
  onTeardown,
  onExport,
  onApplyFix,
}: {
  readonly viewMode: "simple" | "pro";
  readonly setViewMode: (mode: "simple" | "pro") => void;
  readonly detail: LaunchpadRunDetail | null;
  readonly inspector: InspectorItem;
  readonly onInspect: (item: InspectorItem) => void;
  readonly onTeardown: () => void;
  readonly onExport: () => void;
  readonly onApplyFix?: (cli: string) => Promise<void> | void;
}) {
  if (viewMode === "simple") return null;
  if (!detail) return null;
  const instance = detail.instance;
  const receiptRefs = instance.receipts ?? receiptRefStrings(detail.run.receipt_refs) ?? [];

  const canvasNodes = useMemo(() => {
    const gates = detail.gates.map((g) => ({
      id: g.id,
      label: g.label,
      group: g.group,
      verdict: g.verdict,
      proofStatus: g.proof_status,
      summary: g.summary,
    }));
    const events = detail.events.map((e) => ({
      id: e.id,
      label: e.label,
      group: e.stage,
      verdict: e.verdict,
      proofStatus: e.proof_status,
      summary: e.human_summary,
    }));
    return [...gates, ...events];
  }, [detail.gates, detail.events]);

  const canvasEdges = useMemo(() => {
    return canvasNodes.slice(1).map((node, i) => ({
      from: canvasNodes[i].id,
      to: node.id,
    }));
  }, [canvasNodes]);

  const handleSelectNode = (id: string) => {
    const gate = detail.gates.find((g) => g.id === id);
    if (gate) {
      onInspect({ kind: "gate", value: gate });
      return;
    }
    const event = detail.events.find((e) => e.id === id);
    if (event) {
      onInspect({ kind: "event", value: event });
    }
  };

  const selectedNodeId = inspector?.value?.id;

  return (
    <section className="run-detail-grid">
      <ProofPanel detail={detail} onExport={onExport} />
      <div className="launchpad-panel run-detail-main">
        <div className="panel-head">
          <PanelHeader kicker="Run Detail" title={`${detail.run.app_id} run`} description="Every state below is backed by a backend event or shown as unproven." />
          <span className={`launchpad-verdict verdict-${(instance.verdict ?? "ESCALATE").toLowerCase()}`}>{instance.verdict ?? "ESCALATE"}</span>
        </div>
        <dl className="launchpad-facts">
          <ProvenFact label="State" value={instance.state ?? "unproven"} proven={receiptRefs.length > 0} />
          <ProvenFact label="Policy hash" value={detail.run.plan_hash ?? "unproven"} proven={Boolean(detail.run.plan_hash)} />
          <ProvenFact label="LaunchPlan hash" value={instance.launchplan_hash ?? "unproven"} proven={Boolean(instance.launchplan_hash)} />
          <ProvenFact label="Runtime" value={instance.runtime ?? "unproven"} proven={Boolean(instance.runtime && receiptRefs.length > 0)} />
          <ProvenFact label="EvidencePack" value={instance.evidencepack_ref ? "ready" : "unproven"} proven={Boolean(instance.evidencepack_ref)} />
          <ProvenFact label="Offline verify" value={instance.offline_verification_ready ? "available" : "unproven"} proven={Boolean(instance.offline_verify_command)} />
        </dl>
        <div className="launchpad-actions">
          <button type="button" className="launchpad-action" disabled={!instance.evidencepack_ref} onClick={onExport}>
            <Download size={14} aria-hidden="true" /> Export EvidencePack
          </button>
          <button type="button" className="launchpad-action" disabled={!instance.offline_verify_command} onClick={() => void copyText(instance.offline_verify_command ?? "")}>
            <Clipboard size={14} aria-hidden="true" /> Copy verify command
          </button>
          <HumanOnlyActionButton
            label="Teardown"
            cli={instance.teardown_command ?? `helm teardown ${instance.run_id} --cascade`}
            disabled={!instance.run_id}
            disabledReason={!instance.run_id ? "Run id is unproven." : undefined}
            destructive
            onConfirm={onTeardown}
          />
        </div>
        
        {canvasNodes.length > 0 ? (
          <div style={{ marginTop: '16px', marginBottom: '16px' }}>
            <CanvasElement
              nodes={canvasNodes}
              edges={canvasEdges}
              selectedNodeId={selectedNodeId}
              onSelectNode={handleSelectNode}
              width={780}
              height={320}
            />
          </div>
        ) : null}

        <div className="gate-timeline" aria-label="Gate chain">
          {detail.gates.map((gate) => (
            <button key={gate.id} type="button" className={`gate-row proof-${gate.proof_status}`} onClick={() => onInspect({ kind: "gate", value: gate })}>
              <span className={`receipt-state state-${gate.verdict.toLowerCase()}`} />
              <strong>{gate.label}</strong>
              <small>{gate.group}</small>
              <em>{gate.receipt_refs?.length ? "receipt" : gate.proof_status}</em>
            </button>
          ))}
        </div>
        <div className="run-timeline" aria-label="Run event timeline">
          {detail.events.map((event) => (
            <button key={event.id} type="button" className={`gate-row proof-${event.proof_status}`} onClick={() => onInspect({ kind: "event", value: event })}>
              <span className={`receipt-state state-${event.verdict.toLowerCase()}`} />
              <strong>{event.label}</strong>
              <small>{event.human_summary}</small>
              <em>{event.receipt_ref ? "receipt" : "unproven"}</em>
            </button>
          ))}
        </div>
      </div>
      <Inspector item={inspector} onApplyFix={onApplyFix} />
    </section>
  );
}

function Inspector({ item, onApplyFix }: { readonly item: InspectorItem; readonly onApplyFix?: (cli: string) => Promise<void> | void }) {
  const value = item?.value;
  const summary = item?.kind === "event" ? item.value.human_summary : item?.kind === "gate" ? item.value.summary : "";
  const why = item?.kind === "event" ? item.value.why : item?.kind === "gate" ? item.value.why : "";
  const raw = item?.kind === "event" ? item.value.raw_payload_ref : item?.kind === "gate" ? item.value.raw_detail_ref : "";
  const receipt = item?.kind === "event" ? item.value.receipt_ref || "unproven" : item?.kind === "gate" ? item.value.receipt_refs?.join(", ") || "unproven" : "unproven";
  const fixes = value?.fix_actions ?? [];

  const annotations = useMemo<readonly CodeAnnotation[]>(() => {
    if (!value) return [];
    const annList: CodeAnnotation[] = [];
    const jsonStr = JSON.stringify(value, null, 2);
    const lines = jsonStr.split("\n");

    let verdictLine = 1;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes('"verdict"')) {
        verdictLine = i + 1;
        break;
      }
    }

    if (value.verdict !== "ALLOW") {
      const errorText = ("actionable_error" in value && value.actionable_error) || why || "Security Boundary block: verdict is not ALLOW.";
      const firstFix = fixes[0];
      annList.push({
        line: verdictLine,
        text: errorText,
        type: "error",
        fixSuggestion: firstFix?.cli,
        fixLabel: firstFix?.label,
      });
    }

    let proofLine = 1;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes('"proof_status"')) {
        proofLine = i + 1;
        break;
      }
    }

    if (value.proof_status !== "proven" && value.proof_status !== "ALLOW") {
      annList.push({
        line: proofLine,
        text: "Unproven boundary state detected. No cryptographic proof receipt exists for this transition.",
        type: "warning",
      });
    }

    return annList;
  }, [value, why, fixes]);

  const handleApplyInlineFix = async (ann: CodeAnnotation) => {
    if (ann.fixSuggestion && onApplyFix) {
      await onApplyFix(ann.fixSuggestion);
    }
  };

  return (
    <aside className="launchpad-panel inspector-panel">
      <PanelHeader kicker="Inspector" title={value?.label ?? "No event selected"} description="Summary -> Why -> Raw proof -> Fix -> CLI equivalent." />
      {!value ? <div className="launchpad-empty">Select a gate or run event.</div> : null}
      {value ? (
        <>
          <InspectorBlock title="Summary" value={summary} />
          <InspectorBlock title="Why" value={why || "Backend did not return a reason. Treat this state as unproven."} />
          <dl className="launchpad-facts">
            <Fact label="reason_code" value={value.reason_code ?? "none"} />
            <Fact label="verdict" value={value.verdict} />
            <Fact label="proof" value={value.proof_status} />
            <Fact label="receipt" value={receipt} />
            <Fact label="proofgraph_node" value={value.proofgraph_node ?? "unproven"} />
            <Fact label="raw proof" value={raw ?? "unproven"} />
          </dl>
          {"actionable_error" in value && value.actionable_error ? <div className="inline-error"><AlertTriangle size={14} /> {value.actionable_error}</div> : null}
          <FixList fixes={fixes} />
          <div className="cli-equivalent">CLI: {value.cli_equivalent ?? "unproven"}</div>
          <div style={{ marginTop: '16px' }}>
            <AnnotatedCodeBlock
              code={JSON.stringify(value, null, 2)}
              language="json"
              annotations={annotations}
              onApplyFix={handleApplyInlineFix}
            />
          </div>
        </>
      ) : null}
    </aside>
  );
}

function PolicySurface({
  viewMode,
  setViewMode,
  app,
  simulation,
  plan,
  busy,
  onSimulate,
}: {
  readonly viewMode: "simple" | "pro";
  readonly setViewMode: (mode: "simple" | "pro") => void;
  readonly app?: LaunchpadApp;
  readonly simulation: PolicySimulation | null;
  readonly plan: LaunchpadPlanResponse | null;
  readonly busy: boolean;
  readonly onSimulate: () => void;
}) {
  const appId = app?.app_id ?? app?.id ?? "<app>";
  const [selectedSafetyMode, setSelectedSafetyMode] = useState<"safe" | "ask">("safe");

  if (viewMode === "simple") {
    return (
      <section className="launchpad-panel" style={{ border: '1px solid rgba(255,255,255,0.08)' }}>
        <PanelHeader
          kicker="Policy"
          title="Safety Profiles"
          description="These controls explain the current policy posture. Runtime authority still comes from backend preflight and receipts."
        />
        
        <div className="simple-option-grid" style={{ marginTop: '24px' }} aria-label="Select safety profile">
          <button
            type="button"
            className={`simple-option-card ${selectedSafetyMode === "safe" ? "selected" : ""}`}
            onClick={() => setSelectedSafetyMode("safe")}
          >
            <strong>Deny by default</strong>
            <span>Use the AppSpec, policy pack, matrix, and LaunchPlan verdict to decide which actions can start.</span>
            <em>{simulation?.verdict ?? plan?.kernel_verdict ?? "unproven"}</em>
          </button>

          <button
            type="button"
            className={`simple-option-card ${selectedSafetyMode === "ask" ? "selected" : ""}`}
            onClick={() => setSelectedSafetyMode("ask")}
          >
            <strong>Operator approval</strong>
            <span>Approval prompts are valid only when the backend returns approval or escalation state for a concrete gate.</span>
            <em>{simulation?.reason_code ?? plan?.reason_code ?? "no reason code"}</em>
          </button>

          <button
            type="button"
            className="simple-option-card"
            onClick={() => setViewMode("pro")}
          >
            <strong>Developer Mode</strong>
            <span>Inspect raw policy simulation, LaunchPlan hash, backend payloads, and CLI equivalents.</span>
            <em>Developer Mode</em>
          </button>
        </div>

        <div className="simple-checklist" style={{ marginTop: '32px' }}>
          <div className="simple-checklist-item">
            <CheckCircle2 size={16} /> Runtime verdicts remain ALLOW, DENY, or ESCALATE.
          </div>
          <div className="simple-checklist-item">
            <CheckCircle2 size={16} /> Proof must come from Launchpad receipts and EvidencePack refs.
          </div>
          <div className="simple-checklist-item">
            <CheckCircle2 size={16} /> Missing backend facts stay visible as unproven.
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="launchpad-panel">
      <div className="panel-head">
        <PanelHeader kicker="Policy Workbench" title={app?.name ?? "No app selected"} description="Simulation first. Raw policy is the final disclosure layer." />
        <button type="button" className="launchpad-action" disabled={busy || !app} onClick={onSimulate}>Simulate policy</button>
      </div>
      <div className="policy-layers">
        <PolicyLayer title="Plain English" value={simulation?.plain_english ?? "unproven - run policy simulation before trusting this state."} />
        <PolicyLayer title="Structured controls" value={simulation ? JSON.stringify(simulation.structured ?? {}, null, 2) : "unproven"} code />
        {simulation ? (
          <section style={{ gridColumn: '1 / -1' }}>
            <h3>Visual Code Diff</h3>
            <VisualCodeDiff diffLines={simulation.diff ?? []} filename={`${appId}_policy.toml`} title="Policy Simulation Dry-run" />
          </section>
        ) : (
          <PolicyLayer title="Diff" value="unproven" code />
        )}
        <details>
          <summary>Raw canonical payload</summary>
          <pre className="launchpad-code">{JSON.stringify(simulation?.raw ?? { proof_status: "unproven", policy_ref: app?.policy_ref ?? "unproven", plan_hash: plan?.plan_hash ?? "unproven" }, null, 2)}</pre>
        </details>
      </div>
      <dl className="launchpad-facts">
        <ProvenFact label="Simulation receipt" value={simulation?.receipt_ref ?? "unproven"} proven={Boolean(simulation?.receipt_ref || simulation?.proof_status === "proven")} />
        <ProvenFact label="Proof" value={simulation?.proof_status ?? "unproven"} proven={simulation?.proof_status === "proven"} />
      </dl>
      <div className="cli-equivalent">CLI: {simulation?.cli_equivalent ?? `helm policy simulate ${appId}`}</div>
    </section>
  );
}

function PolicyLayer({ title, value, code }: { readonly title: string; readonly value: string; readonly code?: boolean }) {
  return <section><h3>{title}</h3>{code ? <pre className="launchpad-code">{value}</pre> : <p>{value}</p>}</section>;
}

function McpSurface({
  viewMode,
  reviews,
  busy,
  onApprove,
}: {
  readonly viewMode: "simple" | "pro";
  readonly reviews: readonly MCPThreatReview[];
  readonly busy: boolean;
  readonly onApprove: (review: MCPThreatReview) => void;
}) {
  if (viewMode === "simple") {
    return (
      <section className="launchpad-panel" style={{ border: '0.5px solid var(--color-border-subtle)' }}>
        <PanelHeader
          kicker="MCP Firewall"
          title="AI Tool Firewall"
          description="MCP state is loaded from Launchpad threat-review APIs. Unknown or unproven tools remain visibly quarantined."
        />
        <div style={{ display: 'grid', gap: '20px', marginTop: '24px' }}>
          {reviews.map((review) => {
            const isApproved = review.state === "approved";
            const tools = readOnlyTools(review);
            return (
              <article key={review.server_id} className="quarantine-card" style={{ border: `1px solid ${isApproved ? 'var(--color-success)' : 'var(--color-warning)'}`, display: 'grid', gap: '16px', background: 'rgba(21, 23, 27, 0.4)', padding: '24px', borderRadius: '8px', position: 'relative', overflow: 'hidden' }}>
                {!isApproved && <div className="scan-line" />}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                  <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                    <Cpu size={24} style={{ color: isApproved ? 'var(--color-success)' : 'var(--color-warning)' }} />
                    <div>
                      <strong style={{ fontSize: '16px', color: 'var(--color-text-primary)' }}>{review.server_id} Tool Pack</strong>
                      {!isApproved && <span style={{ marginLeft: '12px', fontSize: '9px', fontFamily: 'monospace', padding: '2px 6px', background: 'rgba(255,205,91,0.1)', color: 'var(--color-warning)', border: '0.5px solid rgba(255,205,91,0.3)', borderRadius: '4px' }}>{review.risk_class || "unproven risk"}</span>}
                    </div>
                  </div>
                  <span className={`sota-badge ${isApproved ? "badge-success" : "badge-warning"}`}>
                    {isApproved ? "Approved" : "Quarantined"}
                  </span>
                </div>
                <p style={{ margin: 0, fontSize: '13px', color: 'var(--color-text-secondary)', lineHeight: '1.5' }}>
                  {review.summary || "No backend summary returned for this MCP review."}
                </p>
                <div className="confidence-container" style={{ margin: '8px 0' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--color-text-secondary)', marginBottom: '4px' }}>
                    <span>Proof status</span>
                    <span>{review.proof_status}</span>
                  </div>
                  <div style={{ width: '100%', height: '4px', background: 'rgba(255, 255, 255, 0.1)', borderRadius: '2px', overflow: 'hidden' }}>
                    <div style={{ width: review.proof_status === "proven" ? '100%' : '24%', height: '100%', background: isApproved ? 'var(--color-success)' : 'var(--color-warning)' }} />
                  </div>
                </div>
                <div style={{ background: 'rgba(0, 0, 0, 0.2)', padding: '16px', borderRadius: '6px', border: '0.5px solid var(--color-border-subtle)' }}>
                  <span style={{ fontSize: '11px', fontWeight: 'bold', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Declared Tools inside this pack:</span>
                  <div style={{ display: 'grid', gap: '10px', marginTop: '12px' }}>
                    {review.tools.map((tool) => (
                      <div key={tool.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '13px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <input type="checkbox" className="quarantine-checkbox" checked={isApproved || tool.side_effect_class === "read" || tool.side_effect_class === "readonly"} disabled readOnly />
                          <strong>{tool.name}</strong>
                        </div>
                        <span style={{ color: tool.side_effect_class === "read" || tool.side_effect_class === "readonly" ? 'var(--color-success)' : 'var(--color-warning)', fontSize: '11px', fontFamily: 'monospace' }}>
                          {tool.side_effect_class === "read" || tool.side_effect_class === "readonly" ? "Read-only" : "Requires approval"}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
                {!isApproved && tools.length > 0 && (
                  <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <button
                      type="button"
                      className="lp-btn-primary"
                      disabled={busy}
                      onClick={() => onApprove(review)}
                    >
                      Approve scoped read-only
                    </button>
                    <p style={{ margin: 0, fontSize: '11px', color: 'var(--color-text-muted)' }}>
                      HELM can approve scoped read-only tools when the backend returns an approval path. Other tools remain blocked.
                    </p>
                  </div>
                )}
              </article>
            );
          })}
        </div>
        {reviews.length === 0 ? (
          <div className="launchpad-empty" style={{ textAlign: 'center', padding: '24px 0' }}>
            No MCP tool packages configured or reviewed yet.
          </div>
        ) : null}
      </section>
    );
  }
  return (
    <section className="launchpad-panel">
      <PanelHeader kicker="MCP Firewall" title="Threat reviews" description="Unknown MCP servers and tools remain quarantined. Side effects require a scoped approval receipt." />
      <div className="run-list">
        {reviews.map((review) => (
          <article className="mcp-review" key={review.server_id}>
            <div className="mcp-review-head">
              <strong>{review.server_id}</strong>
              <span className={`launchpad-verdict verdict-${review.state === "approved" ? "allow" : "escalate"}`}>{review.state}</span>
            </div>
            <dl className="launchpad-facts">
              <Fact label="Identity" value={`${review.transport ?? "unproven"} ${review.endpoint ?? ""}`} />
              <Fact label="Source" value={review.package_source ?? "unproven"} />
              <Fact label="Digest" value={review.digest ?? "unproven"} />
              <Fact label="Signature" value={review.signature ?? "unproven"} />
              <Fact label="Approval" value={review.approval_receipt ?? "unproven"} />
              <Fact label="Dispatch" value={review.last_dispatch_receipt ?? "none"} />
              <Fact label="Unknown tools" value={review.unknown_tools ? "quarantined" : "none reported"} />
              <ProvenFact label="Review proof" value={review.proof_status} proven={review.proof_status === "proven" || Boolean(review.approval_receipt)} />
            </dl>
            <p>{review.summary}</p>
            <McpToolList review={review} />
            <FixList fixes={review.fix_actions ?? []} emptyMessage="Unknown tools stay quarantined unless a human grants a scoped approval receipt." />
            <HumanOnlyActionButton
              label="Approve scoped read-only"
              cli={mcpApprovalCli(review)}
              disabled={busy || review.state === "approved" || readOnlyTools(review).length === 0}
              disabledReason={review.state === "approved" ? "Already approved." : readOnlyTools(review).length === 0 ? "No read-only tools are eligible for approval." : undefined}
              onConfirm={() => onApprove(review)}
            />
          </article>
        ))}
      </div>
      {reviews.length === 0 ? <div className="launchpad-empty">No MCP threat reviews returned by backend.</div> : null}
    </section>
  );
}

function SecretsSurface({
  viewMode,
  secrets,
  apps,
  busy,
  onBindSecret,
}: {
  readonly viewMode: "simple" | "pro";
  readonly secrets: readonly LaunchpadSecretGrant[];
  readonly apps: readonly LaunchpadApp[];
  readonly busy: boolean;
  readonly onBindSecret: (requirement: SecretRequirement) => void;
}) {
  const required = apps.flatMap((item) => secretRequirements(item, secrets).map((requirement) => ({ app: item.name, requirement })));

  if (viewMode === "simple") {
    return (
      <section className="launchpad-panel">
        <PanelHeader
          kicker="Secrets"
          title="Environment-backed secret grants"
          description="Launchpad secret routes bind logical secret names to environment variable names. This Console does not collect raw secret values."
        />
        <div className="simple-safety-grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "16px", marginTop: "16px" }}>
          {required.map((item) => {
            const req = item.requirement;
            return (
              <div key={`${item.app}:${req.logical}:${req.env}`} className="simple-safety-card" style={{ padding: "20px", display: "grid", gap: "12px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontWeight: "bold", fontSize: "var(--font-size-md)", color: "var(--lp-text)" }}>{req.logical}</span>
                  {req.present ? (
                    <span className="badge" style={{ backgroundColor: "rgba(34, 197, 94, 0.1)", color: "var(--lp-allow)", padding: "4px 8px", borderRadius: "12px", display: "flex", alignItems: "center", gap: "4px", fontSize: "var(--font-size-xs)" }}>
                      <CheckCircle2 size={12} /> Present
                    </span>
                  ) : (
                    <span className="badge" style={{ backgroundColor: "rgba(239, 68, 68, 0.1)", color: "var(--lp-escalate)", padding: "4px 8px", borderRadius: "12px", display: "flex", alignItems: "center", gap: "4px", fontSize: "var(--font-size-xs)" }}>
                      <Key size={12} /> Needs Activation
                    </span>
                  )}
                </div>
                <p style={{ margin: 0, color: "var(--lp-text-dim)", fontSize: "var(--font-size-sm)", lineHeight: "1.4" }}>
                  {req.present 
                    ? `Backend status reports ${req.env} is available for launch-scoped projection.`
                    : `The Kernel process does not expose ${req.env}. Set it in the environment, then bind the env name.`}
                </p>
                {!req.present && (
                  <button
                    type="button"
                    className="launchpad-action-primary"
                    style={{ width: "100%", padding: "8px", justifySelf: "start", marginTop: "4px" }}
                    disabled={busy}
                    onClick={() => onBindSecret(req)}
                  >
                    Activate Connection ({req.env})
                  </button>
                )}
              </div>
            );
          })}
          {required.length === 0 && (
            <div className="launchpad-empty" style={{ gridColumn: "1 / -1" }}>No security integration keys are required by your current apps.</div>
          )}
        </div>
      </section>
    );
  }

  return (
    <section className="launchpad-panel">
      <PanelHeader kicker="Secret Grants" title="Required runtime grants" description="Raw secret values never cross this API or UI." />
      <div className="run-list">
        {required.map((item) => {
          const grant = item.requirement.grant;
          return (
            <button key={`${item.app}:${item.requirement.logical}:${item.requirement.env}`} type="button">
              <strong>{item.requirement.logical}</strong>
              <span>{item.requirement.present ? "present" : "missing"}</span>
              <em>{grant?.scope ?? "runtime env"}</em>
              <code>{grant?.grant_hash ?? "unproven"}</code>
            </button>
          );
        })}
      </div>
      <SecretFixPanel requirements={required.map((item) => item.requirement).filter((requirement) => !requirement.present)} busy={busy} onBindSecret={onBindSecret} />
      <div className="cli-equivalent">CLI: helm secret status</div>
    </section>
  );
}

function EvidenceSurface({
  viewMode,
  runs,
  detail,
  onExport,
}: {
  readonly viewMode: "simple" | "pro";
  readonly runs: readonly LaunchpadRun[];
  readonly detail: LaunchpadRunDetail | null;
  readonly onExport: () => void;
}) {
  const refs = uniqueStrings([
    ...runs.flatMap((run) => run.evidence_pack_refs ?? []),
    detail?.instance.evidencepack_ref ?? "",
    ...(detail?.instance.evidencepack_refs ?? []),
  ]);

  if (viewMode === "simple") {
    return <ProofPanel detail={detail} onExport={onExport} />;
  }

  return (
    <section className="launchpad-panel">
      <div className="panel-head">
        <PanelHeader kicker="Evidence" title="EvidencePacks" description="Proof product, not an audit-log dump. Offline verification stays separate from local UI status." />
        <button type="button" className="launchpad-action" disabled={!detail?.instance.evidencepack_ref} onClick={onExport}>
          <Download size={14} aria-hidden="true" /> Export EvidencePack
        </button>
      </div>
      <dl className="launchpad-facts">
        <Fact label="Verified by HELM locally" value={detail?.instance.local_verification_status ?? "unproven"} />
        <Fact label="Offline command" value={detail?.instance.offline_verify_command ? "available" : "unproven"} />
        <Fact label="Without HELM Cloud" value={detail?.instance.offline_verification_ready ? "yes" : "unproven"} />
      </dl>
      <button type="button" className="launchpad-action" disabled={!detail?.instance.offline_verify_command} onClick={() => void copyText(detail?.instance.offline_verify_command ?? "")}>
        <Clipboard size={14} aria-hidden="true" /> Copy offline verify command
      </button>
      <ul className="launchpad-list evidencepack-list">
        {refs.map((ref) => {
          const command = detail?.instance.offline_verify_command ?? `helm evidence verify ${ref} --offline`;
          return (
            <li key={ref}>
              <span>EvidencePack</span>
              <code>{ref}</code>
              <small>{detail?.instance.local_verification_status ?? "unproven"}</small>
              <button type="button" className="launchpad-action" onClick={() => void copyText(command)}>
                <Clipboard size={14} aria-hidden="true" /> Copy verify CLI
              </button>
              <code>{command}</code>
            </li>
          );
        })}
      </ul>
      {refs.length === 0 ? <div className="launchpad-empty">No EvidencePack refs returned; offline verification is unproven.</div> : null}
      <div className="cli-equivalent">CLI: {detail?.instance.offline_verify_command ?? "helm evidence verify <file> --offline"}</div>
    </section>
  );
}

function SandboxSurface({
  viewMode,
  grant,
  detail,
}: {
  readonly viewMode: "simple" | "pro";
  readonly grant: SandboxGrantView | null;
  readonly detail: LaunchpadRunDetail | null;
}) {
  if (viewMode === "simple") {
    const folders = grant?.filesystem_preopens ?? [];
    const domains = grant?.network_policy ?? [];
    
    return (
      <section className="launchpad-panel">
        <PanelHeader
          kicker="Sandbox"
          title="Runtime boundary facts"
          description="Sandbox details are shown from backend grant data. Missing grant data stays unproven."
        />
        <div style={{ display: "grid", gap: "16px", marginTop: "20px" }}>
          <div className="simple-safety-card" style={{ padding: "20px" }}>
            <div style={{ display: "flex", gap: "12px", alignItems: "center", marginBottom: "12px" }}>
              <FolderOpen size={20} style={{ color: "var(--lp-allow)" }} />
              <strong style={{ fontSize: "var(--font-size-md)" }}>Allowed Folders</strong>
            </div>
            <p style={{ margin: "0 0 12px 0", color: "var(--lp-text-dim)", fontSize: "var(--font-size-sm)", lineHeight: "1.4" }}>
              Filesystem preopens are the backend-reported paths for the selected run.
            </p>
            {folders.length > 0 ? (
              <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                {folders.map((f) => (
                  <code key={f} style={{ background: "rgba(255,255,255,0.05)", padding: "4px 8px", borderRadius: "4px", fontSize: "var(--font-size-xs)" }}>{f}</code>
                ))}
              </div>
            ) : (
              <span style={{ color: "var(--lp-text-dim)", fontStyle: "italic", fontSize: "var(--font-size-sm)" }}>No folder pre-opens active. Isolated from filesystem.</span>
            )}
          </div>

          <div className="simple-safety-card" style={{ padding: "20px" }}>
            <div style={{ display: "flex", gap: "12px", alignItems: "center", marginBottom: "12px" }}>
              <Globe size={20} style={{ color: "var(--lp-allow)" }} />
              <strong style={{ fontSize: "var(--font-size-md)" }}>Allowed API Networks</strong>
            </div>
            <p style={{ margin: "0 0 12px 0", color: "var(--lp-text-dim)", fontSize: "var(--font-size-sm)", lineHeight: "1.4" }}>
              Network entries are the backend-reported allowlist for the selected run.
            </p>
            {domains.length > 0 ? (
              <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                {domains.map((d) => (
                  <code key={d} style={{ background: "rgba(255,255,255,0.05)", padding: "4px 8px", borderRadius: "4px", fontSize: "var(--font-size-xs)" }}>{d}</code>
                ))}
              </div>
            ) : (
              <span style={{ color: "var(--lp-text-dim)", fontStyle: "italic", fontSize: "var(--font-size-sm)" }}>All outbound network requests are entirely blocked by default.</span>
            )}
          </div>

          <div className="simple-safety-card" style={{ padding: "20px", display: "flex", gap: "12px", alignItems: "center" }}>
            <ShieldCheck size={24} style={{ color: "var(--lp-allow)", flexShrink: 0 }} />
            <div>
              <strong style={{ fontSize: "var(--font-size-sm)", display: "block" }}>Hardware Sandbox</strong>
              <span style={{ color: "var(--lp-text-dim)", fontSize: "var(--font-size-xs)" }}>Hardened Dedicated Virtual Machine (gVisor isolated)</span>
            </div>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="launchpad-panel">
      <PanelHeader kicker="Sandbox" title="Runtime grant" description="Backend-computed grant for the selected run. No app fallback is inferred by the UI." />
      <dl className="launchpad-facts">
        <Fact label="Backend" value={grant?.backend_profile ?? "unproven"} />
        <Fact label="Runtime" value={grant ? `${grant.runtime} ${grant.runtime_version}` : "unproven"} />
        <Fact label="Image" value={grant?.image_digest ?? "unproven"} />
        <Fact label="Filesystem" value={grant?.filesystem_preopens?.join(", ") ?? "unproven"} />
        <Fact label="Network" value={grant?.network_policy?.join(", ") ?? "unproven"} />
        <Fact label="Env" value={grant?.env?.join(", ") ?? "unproven"} />
        <Fact label="Grant hash" value={grant?.grant_hash ?? "unproven"} />
      </dl>
      <div className="cli-equivalent">CLI: helm sandbox inspect {detail?.instance.run_id ?? "<run_id>"}</div>
    </section>
  );
}

function ReceiptsSurface({
  viewMode,
  receipts,
  detail,
}: {
  readonly viewMode: "simple" | "pro";
  readonly receipts: readonly string[];
  readonly detail: LaunchpadRunDetail | null;
}) {
  if (viewMode === "simple") {
    const hasReceipts = receipts.length > 0;
    
    return (
      <section className="launchpad-panel">
        <PanelHeader
          kicker="Receipts"
          title="Run receipt refs"
          description="Receipt refs are listed only when returned by the Launchpad backend."
        />
        <div style={{ display: "grid", gap: "16px", marginTop: "20px" }}>
          {hasReceipts ? (
            <div className="simple-safety-card" style={{ padding: "24px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "16px" }}>
                <ShieldCheck size={20} style={{ color: "var(--lp-allow)" }} />
                <strong style={{ fontSize: "var(--font-size-md)" }}>{receipts.length} receipt ref(s) returned</strong>
              </div>
              <ul className="launchpad-list">
                {receipts.map((receipt) => <li key={receipt}><span>receipt</span><code>{receipt}</code></li>)}
              </ul>
            </div>
          ) : (
            <div className="launchpad-empty">
              No receipt refs returned yet.
            </div>
          )}
        </div>
      </section>
    );
  }

  return (
    <section className="launchpad-panel">
      <PanelHeader kicker="Receipts" title="Run receipts" description="No receipt means unproven." />
      <ul className="launchpad-list">
        {receipts.map((receipt) => <li key={receipt}><span>receipt</span><code>{receipt}</code></li>)}
      </ul>
      {receipts.length === 0 ? <div className="launchpad-empty">unproven</div> : null}
      <div className="cli-equivalent">CLI: helm run receipts {detail?.instance.run_id ?? "<run_id>"}</div>
    </section>
  );
}

function RegistrySurface({ apps, substrates, matrix }: { readonly apps: readonly LaunchpadApp[]; readonly substrates: readonly LaunchpadSubstrate[]; readonly matrix: readonly LaunchpadMatrixCell[] }) {
  const [query, setQuery] = useState("");
  const filtered = apps.filter((item) => `${item.name} ${item.app_id ?? item.id}`.toLowerCase().includes(query.toLowerCase()));
  return (
    <section className="launchpad-panel">
      <PanelHeader kicker="Registry" title="AppSpec inspector" description="Searchable registry objects with raw payload as final disclosure." />
      <label className="launchpad-field">
        <span>Search AppSpecs</span>
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="openclaw, hermes, opencode" />
      </label>
      <div className="launchpad-metrics">
        <span><strong>{apps.length}</strong> apps</span>
        <span><strong>{substrates.length}</strong> substrates</span>
        <span><strong>{matrix.length}</strong> cells</span>
      </div>
      <div className="registry-list">
        {filtered.map((item) => (
          <details key={item.app_id ?? item.id}>
            <summary>{item.name} <span>{item.status?.verdict ?? "ESCALATE"}</span></summary>
            <dl className="launchpad-facts">
              <Fact label="AppSpec" value={item.app_id ?? item.id} />
              <Fact label="Source" value={item.oci_ref ?? "unproven"} />
              <Fact label="Digest" value={item.immutable_digest ?? "unproven"} />
              <Fact label="Policy" value={item.policy_ref ?? "unproven"} />
            </dl>
            <details>
              <summary>Raw AppSpec read model</summary>
              <pre className="launchpad-code">{JSON.stringify(item, null, 2)}</pre>
            </details>
          </details>
        ))}
      </div>
    </section>
  );
}

function InspectorBlock({ title, value }: { readonly title: string; readonly value: string }) {
  return (
    <section className="inspector-block">
      <h3>{title}</h3>
      <p>{value}</p>
    </section>
  );
}

function FixList({ fixes, emptyMessage = "No backend fix action returned." }: { readonly fixes: readonly FixAction[]; readonly emptyMessage?: string }) {
  if (fixes.length === 0) {
    return <InspectorBlock title="Fix" value={emptyMessage} />;
  }
  return (
    <section className="inspector-block">
      <h3>Fix</h3>
      <ul className="launchpad-list">
        {fixes.map((fix) => <li key={`${fix.label}:${fix.cli}`}><span>{fix.label}</span><code>{fix.cli}</code></li>)}
      </ul>
    </section>
  );
}

function SecretFixPanel({ requirements, busy, onBindSecret }: { readonly requirements: readonly SecretRequirement[]; readonly busy: boolean; readonly onBindSecret: (requirement: SecretRequirement) => void }) {
  if (requirements.length === 0) return null;
  return (
    <section className="secret-fix-panel" aria-label="Missing secret fixes">
      <strong>Missing secret blocks launch</strong>
      <p>Set the environment variable, then bind the logical AppSpec secret. HELM AI cannot inject secrets.</p>
      <ul className="launchpad-list">
        {requirements.map((requirement) => (
          <li key={`${requirement.logical}:${requirement.env}`}>
            <span>{requirement.logical}</span>
            <code>{requirement.env}</code>
            <button type="button" className="launchpad-action" disabled={busy} onClick={() => onBindSecret(requirement)}>
              Bind env grant
            </button>
            <code>{requirement.cli}</code>
          </li>
        ))}
      </ul>
    </section>
  );
}

function McpToolList({ review }: { readonly review: MCPThreatReview }) {
  if (review.tools.length === 0) {
    return <div className="launchpad-empty">No tool manifest returned; server remains quarantined.</div>;
  }
  return (
    <div className="mcp-tool-list" aria-label={`${review.server_id} MCP tool permissions`}>
      {review.tools.map((tool) => (
        <article key={tool.name}>
          <strong>{tool.name}</strong>
          <dl className="launchpad-facts">
            <Fact label="Side effect" value={tool.side_effect_class} />
            <Fact label="Approval" value={tool.approval_state} />
            <Fact label="Filesystem" value={tool.filesystem_needs?.join(", ") || "none"} />
            <Fact label="Network" value={tool.network_needs?.join(", ") || "none"} />
            <Fact label="Secrets" value={tool.secret_needs?.join(", ") || "none"} />
            <Fact label="Dispatch" value={tool.dispatch_receipt ?? "unproven"} />
          </dl>
        </article>
      ))}
    </div>
  );
}

function InlineBlock({ title, items }: { readonly title: string; readonly items: readonly string[] }) {
  if (items.length === 0) return null;
  return (
    <div className="inline-error" role="status">
      <AlertTriangle size={14} aria-hidden="true" />
      <span><strong>{title}:</strong> {items.join(" ")}</span>
    </div>
  );
}

function HumanOnlyActionButton({
  label,
  icon,
  cli,
  disabled,
  disabledReason,
  primary,
  destructive,
  onConfirm,
}: {
  readonly label: string;
  readonly icon?: ReactNode;
  readonly cli: string;
  readonly disabled?: boolean;
  readonly disabledReason?: string;
  readonly primary?: boolean;
  readonly destructive?: boolean;
  readonly onConfirm: () => void;
}) {
  const [confirmed, setConfirmed] = useState(false);
  const blocked = disabled || !confirmed;
  return (
    <div className={`human-action-gate${destructive ? " destructive" : ""}`}>
      <label>
        <input type="checkbox" disabled={disabled} checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
        <span>Human operator confirms. HELM AI cannot authorize this side effect.</span>
      </label>
      {disabledReason ? <small>{disabledReason}</small> : null}
      <button type="button" className={`launchpad-action${primary ? " launchpad-action-primary" : ""}`} disabled={blocked} onClick={onConfirm}>
        {icon} {label}
      </button>
      <div className="cli-equivalent">CLI: {cli}</div>
    </div>
  );
}

function ProvenFact({ label, value, proven }: { readonly label: string; readonly value: string; readonly proven: boolean }) {
  return <Fact label={label} value={`${value} (${proven ? "proven" : "unproven"})`} />;
}

function Fact({ label, value }: { readonly label: string; readonly value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}

async function copyText(value: string) {
  if (!value) return;
  await navigator.clipboard?.writeText(value);
}

function secretRequirements(app: LaunchpadApp, secrets: readonly LaunchpadSecretGrant[]): SecretRequirement[] {
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
      grant,
      cli: `helm secret set ${logical} --provider env --value-env ${env}`,
    };
  });
}

function launchBlockedReasons(app: LaunchpadApp, cell: LaunchpadMatrixCell | undefined, missing: readonly SecretRequirement[], reviews: readonly MCPThreatReview[]): string[] {
  const reasons: string[] = [];
  if ((app.status?.verdict ?? "ESCALATE") !== "ALLOW") reasons.push(app.status?.summary ?? app.blocked_reason ?? "App status is not ALLOW.");
  if (!cell) reasons.push("Compatibility matrix cell is unproven.");
  if (cell && (!cell.launchable || cell.verdict !== "ALLOW")) reasons.push(cell.reason || "Compatibility matrix blocks launch.");
  if (missing.length > 0) reasons.push(`Missing secret: ${missing.map((item) => `${item.logical} from ${item.env}`).join(", ")}.`);
  const confusingMcp = reviews.filter((review) => !["approved", "quarantined"].includes(review.state));
  if (confusingMcp.length > 0) reasons.push(`MCP state is not approved or quarantined: ${confusingMcp.map((review) => review.server_id).join(", ")}.`);
  return uniqueStrings(reasons);
}

function sandboxSummary(app: LaunchpadApp): string {
  const limits = app.declared_capabilities?.join(", ") || "AppSpec grant only";
  return `${limits}; no runtime without receipt`;
}

function readOnlyTools(review: MCPThreatReview): string[] {
  return review.tools.filter((tool) => isReadOnlyTool(tool.side_effect_class)).map((tool) => tool.name);
}

function isReadOnlyTool(sideEffectClass: string | undefined): boolean {
  return ["", "t0", "read", "readonly", "read-only", "none"].includes(String(sideEffectClass ?? "").toLowerCase());
}

function mcpApprovalCli(review: MCPThreatReview): string {
  const tools = readOnlyTools(review);
  return review.cli_equivalent ?? `helm mcp approve ${review.server_id} --tools ${tools.join(",")} --ttl 1h --reason "human-scoped read-only Console approval"`;
}

function receiptRefStrings(refs: LaunchpadRun["receipt_refs"] | undefined): string[] | undefined {
  if (!refs) return undefined;
  return refs.map((ref) => {
    if (typeof ref === "string") return ref;
    const value = (ref as { ref?: unknown }).ref;
    return typeof value === "string" ? value : "";
  }).filter(Boolean);
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}
