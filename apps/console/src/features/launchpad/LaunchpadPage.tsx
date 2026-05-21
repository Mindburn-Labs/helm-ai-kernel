import { AlertTriangle, CheckCircle2, Clipboard, Download, Loader2, Play, RefreshCw, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { launchpadApi } from "./api";
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
  const [runLog, setRunLog] = useState("");
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

  return (
    <div className="launchpad-surface" aria-busy={loading || busy}>
      <section className="launchpad-panel launchpad-hero">
        <PanelHeader
          kicker="HELM Console"
          title="Launch / Run Timeline"
          description="Universal execution boundary: AppSpec -> Preflight -> LaunchPlan -> policy -> grants -> MCP quarantine -> runtime -> receipts -> EvidencePack -> offline verify."
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
          <span><strong>{threatReviews.length}</strong> MCP reviews</span>
        </div>
      </section>

      {notice?.tone === "error" ? (
        <div className="inline-error" role="alert">
          <AlertTriangle size={14} /> {notice.message}
        </div>
      ) : null}

      {surface === "launch" || surface === "apps" ? (
        <LaunchSurface
          apps={apps}
          matrix={matrix}
          secrets={secrets}
          threatReviews={threatReviews}
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

      {surface === "runs" ? <RunsSurface runs={runs} detail={detail} busy={busy} onOpenRun={(id) => void openRun(id)} onTeardown={() => void teardown()} /> : null}
      {surface === "policies" ? <PolicySurface app={app} simulation={policySimulation} plan={plan} busy={busy} onSimulate={() => void simulatePolicy()} /> : null}
      {surface === "mcp" ? <McpSurface reviews={threatReviews} busy={busy} onApprove={(review) => void approveMcpReview(review)} /> : null}
      {surface === "secrets" ? <SecretsSurface secrets={secrets} apps={apps} busy={busy} onBindSecret={(requirement) => void bindSecret(requirement)} /> : null}
      {surface === "evidence" ? <EvidenceSurface runs={runs} detail={detail} onExport={() => void exportEvidence()} /> : null}
      {surface === "sandbox" ? <SandboxSurface grant={sandboxGrant ?? detail?.instance.sandbox_grant ?? null} detail={detail} /> : null}
      {surface === "receipts" ? <ReceiptsSurface receipts={receipts.length ? receipts : detail?.instance.receipts ?? []} detail={detail} /> : null}
      {surface === "registry" ? <RegistrySurface apps={apps} substrates={substrates} matrix={matrix} /> : null}

      <RunDetail detail={detail} inspector={inspector} onInspect={setInspector} onTeardown={() => void teardown()} onExport={() => void exportEvidence()} />
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
  apps,
  matrix,
  secrets,
  threatReviews,
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
  readonly apps: readonly LaunchpadApp[];
  readonly matrix: readonly LaunchpadMatrixCell[];
  readonly secrets: readonly LaunchpadSecretGrant[];
  readonly threatReviews: readonly MCPThreatReview[];
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
          const status = item.status;
          const cell = matrix.find((entry) => entry.app_id === appId && entry.substrate_id === selectedSubstrate);
          const requirements = secretRequirements(item, secrets);
          const missingRequirements = requirements.filter((requirement) => !requirement.present || status?.missing_secrets?.includes(requirement.env) || status?.missing_secrets?.includes(requirement.logical));
          const appReviews = threatReviews.filter((review) => review.app_id === appId);
          const blockedReasons = launchBlockedReasons(item, cell, missingRequirements, appReviews);
          const canLaunch = blockedReasons.length === 0 && selectedSubstrate !== "";
          const launchCli = `helm app run ${appId}${selectedSubstrate ? ` --substrate ${selectedSubstrate}` : ""}`;
          return (
            <article key={appId} className={`appspec-card status-${status?.state ?? "unknown"}`}>
              <button type="button" className="appspec-main" aria-pressed={selectedApp === appId} onClick={() => onSelectApp(appId)}>
                <span className="appspec-title-row">
                  <strong>{item.name}</strong>
                  <span className={`launchpad-verdict verdict-${(status?.verdict ?? "ESCALATE").toLowerCase()}`}>{status?.verdict ?? "ESCALATE"}</span>
                </span>
                <code>{item.oci_ref ?? item.immutable_digest ?? "artifact unproven"}</code>
                <span>{status?.summary ?? item.blocked_reason ?? "No backend status returned."}</span>
              </button>
              <dl className="launchpad-facts">
                <Fact label="Status" value={status?.state ?? "unknown"} />
                <Fact label="Matrix" value={cell ? `${cell.verdict} - ${cell.reason}` : "unproven"} />
                <Fact label="Policy" value={item.policy_ref ?? "unproven"} />
                <Fact label="Secrets" value={`${requirements.length} required, ${missingRequirements.length} missing`} />
                <Fact label="MCP" value={`${item.mcp_servers?.length ?? 0} declared, ${appReviews.length} reviewed`} />
                <Fact label="Filesystem" value={item.filesystem_needs?.join(", ") || "deny by default"} />
                <Fact label="Network" value={item.network_needs?.join(", ") || "deny by default"} />
                <Fact label="Model env" value={item.model_gateway_env?.join(", ") || "none"} />
                <Fact label="Sandbox" value={sandboxSummary(item)} />
                <Fact label="Healthcheck" value={item.healthcheck?.length ? `${item.healthcheck.length} declared` : "unproven"} />
                <Fact label="Teardown" value={item.teardown_recipe ? "cascade recipe declared" : "unproven"} />
                <Fact label="EvidencePack" value={status?.last_evidence_pack ? "available" : "unproven"} />
              </dl>
              {missingRequirements.length > 0 ? <SecretFixPanel requirements={missingRequirements} busy={busy} onBindSecret={onBindSecret} /> : null}
              {blockedReasons.length > 0 ? <InlineBlock title="Launch blocked" items={blockedReasons} /> : null}
              <div className="cli-equivalent">Preflight CLI: helm app preflight {appId}{selectedSubstrate ? ` --substrate ${selectedSubstrate}` : ""}</div>
              <div className="cli-equivalent">Launch CLI: {launchCli}</div>
              <div className="launchpad-actions">
                <button type="button" className="launchpad-action" disabled={busy} onClick={() => onPreflight(appId)}>Preflight</button>
                <HumanOnlyActionButton
                  label="Launch"
                  icon={<Play size={14} aria-hidden="true" />}
                  cli={launchCli}
                  disabled={busy || !canLaunch}
                  disabledReason={blockedReasons[0]}
                  primary
                  onConfirm={() => onLaunch(appId)}
                />
              </div>
              {selectedApp === appId ? <span className="launchpad-ready"><CheckCircle2 size={13} aria-hidden="true" /> selected</span> : null}
            </article>
          );
        })}
      </section>
    </>
  );
}

function RunsSurface({ runs, detail, busy, onOpenRun, onTeardown }: { readonly runs: readonly LaunchpadRun[]; readonly detail: LaunchpadRunDetail | null; readonly busy: boolean; readonly onOpenRun: (id: string) => void; readonly onTeardown: () => void }) {
  const runId = detail?.instance.run_id ?? detail?.run.launch_id ?? "<run_id>";
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

function RunDetail({ detail, inspector, onInspect, onTeardown, onExport }: { readonly detail: LaunchpadRunDetail | null; readonly inspector: InspectorItem; readonly onInspect: (item: InspectorItem) => void; readonly onTeardown: () => void; readonly onExport: () => void }) {
  if (!detail) return null;
  const instance = detail.instance;
  const receiptRefs = instance.receipts ?? receiptRefStrings(detail.run.receipt_refs) ?? [];
  return (
    <section className="run-detail-grid">
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
      <Inspector item={inspector} />
    </section>
  );
}

function Inspector({ item }: { readonly item: InspectorItem }) {
  const value = item?.value;
  const summary = item?.kind === "event" ? item.value.human_summary : item?.kind === "gate" ? item.value.summary : "";
  const why = item?.kind === "event" ? item.value.why : item?.kind === "gate" ? item.value.why : "";
  const raw = item?.kind === "event" ? item.value.raw_payload_ref : item?.kind === "gate" ? item.value.raw_detail_ref : "";
  const receipt = item?.kind === "event" ? item.value.receipt_ref || "unproven" : item?.kind === "gate" ? item.value.receipt_refs?.join(", ") || "unproven" : "unproven";
  const fixes = value?.fix_actions ?? [];
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
          <details>
            <summary>Raw backend payload</summary>
            <pre className="launchpad-code">{JSON.stringify(value, null, 2)}</pre>
          </details>
        </>
      ) : null}
    </aside>
  );
}

function PolicySurface({ app, simulation, plan, busy, onSimulate }: { readonly app?: LaunchpadApp; readonly simulation: PolicySimulation | null; readonly plan: LaunchpadPlanResponse | null; readonly busy: boolean; readonly onSimulate: () => void }) {
  const appId = app?.app_id ?? app?.id ?? "<app>";
  return (
    <section className="launchpad-panel">
      <div className="panel-head">
        <PanelHeader kicker="Policy Workbench" title={app?.name ?? "No app selected"} description="Simulation first. Raw policy is the final disclosure layer." />
        <button type="button" className="launchpad-action" disabled={busy || !app} onClick={onSimulate}>Simulate policy</button>
      </div>
      <div className="policy-layers">
        <PolicyLayer title="Plain English" value={simulation?.plain_english ?? "unproven - run policy simulation before trusting this state."} />
        <PolicyLayer title="Structured controls" value={simulation ? JSON.stringify(simulation.structured ?? {}, null, 2) : "unproven"} code />
        <PolicyLayer title="Diff" value={simulation ? (simulation.diff ?? []).join("\n") || "no diff returned" : "unproven"} code />
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

function McpSurface({ reviews, busy, onApprove }: { readonly reviews: readonly MCPThreatReview[]; readonly busy: boolean; readonly onApprove: (review: MCPThreatReview) => void }) {
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

function SecretsSurface({ secrets, apps, busy, onBindSecret }: { readonly secrets: readonly LaunchpadSecretGrant[]; readonly apps: readonly LaunchpadApp[]; readonly busy: boolean; readonly onBindSecret: (requirement: SecretRequirement) => void }) {
  const required = apps.flatMap((item) => secretRequirements(item, secrets).map((requirement) => ({ app: item.name, requirement })));
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

function EvidenceSurface({ runs, detail, onExport }: { readonly runs: readonly LaunchpadRun[]; readonly detail: LaunchpadRunDetail | null; readonly onExport: () => void }) {
  const refs = uniqueStrings([
    ...runs.flatMap((run) => run.evidence_pack_refs ?? []),
    detail?.instance.evidencepack_ref ?? "",
    ...(detail?.instance.evidencepack_refs ?? []),
  ]);
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

function SandboxSurface({ grant, detail }: { readonly grant: SandboxGrantView | null; readonly detail: LaunchpadRunDetail | null }) {
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

function ReceiptsSurface({ receipts, detail }: { readonly receipts: readonly string[]; readonly detail: LaunchpadRunDetail | null }) {
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
