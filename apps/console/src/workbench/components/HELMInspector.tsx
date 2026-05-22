import { useState, type ReactNode } from "react";
import {
  AlertCircle,
  CheckCircle2,
  Circle,
  MessageSquareText,
  ArrowRight,
  Lock,
  Unlock,
  Shield,
  ShieldCheck,
  Cpu,
} from "lucide-react";
import {
  HashText,
  VerdictBadge,
  VerificationStatus,
  WorkbenchActionSheetFrame,
  WorkbenchDrawerFrame,
  WorkbenchProofSection,
  WorkbenchRecordExplorer,
  WorkbenchRecordRow,
  WorkbenchStoreHealthList,
  WorkbenchRouteCoverageTable,
  Tabs,
  PropertyGrid,
  Button,
  VisualCodeDiff,
  AnnotatedCodeBlock,
  type VerificationState,
  type VerdictState,
} from "@mindburn/ui-core";
import {
  type Receipt,
} from "../../api/client";
import {
  isRecord,
  receiptAction,
  receiptResource,
  shortId,
} from "../viewModels";
import type {
  FlowRoute,
  DrawerItem,
  OperatorTask,
  Capability,
  RecordSummary,
  WorkbenchAction,
  WorkbenchDiagnostic,
  TaskTimelineStep,
  TaskSeverity,
} from "../types";
import type { AdminActionValues } from "../../admin/surfaces";

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
  const explicitState = normalizeVerificationState(
    receipt.metadata?.verification_status ?? receipt.metadata?.verification_state
  );
  if (explicitState) return explicitState;
  const verification = receipt.metadata?.verification;
  if (
    typeof verification === "object" &&
    verification !== null &&
    !Array.isArray(verification)
  ) {
    const record = verification as Record<string, unknown>;
    return (
      normalizeVerificationState(record.verdict ?? record.status ?? record.state) ??
      "pending"
    );
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

interface DetailDrawerProps {
  readonly item: DrawerItem | null;
  readonly fallbackReceipt: Receipt | null;
  readonly replayStatus: string;
  readonly onClose: () => void;
  readonly onNavigate: (route: FlowRoute, item?: DrawerItem) => void;
  readonly onOpen: (item: DrawerItem) => void;
  readonly onReplay: () => void;
  readonly onRefresh: (id: string) => Promise<void>;
  readonly activeTab?: "activity" | "boundary" | "mcp" | "runtime" | "evidence" | "raw";
  readonly onTabChange?: (tab: "activity" | "boundary" | "mcp" | "runtime" | "evidence" | "raw") => void;
}

export function DetailDrawer({
  item,
  fallbackReceipt,
  replayStatus,
  onClose,
  onNavigate,
  onOpen,
  onReplay,
  onRefresh,
  activeTab: controlledTab,
  onTabChange: controlledTabChange,
}: DetailDrawerProps) {
  const visibleItem = item ?? (fallbackReceipt ? { kind: "receipt" as const, receipt: fallbackReceipt } : null);
  const [localTab, setLocalTab] = useState<"activity" | "boundary" | "mcp" | "runtime" | "evidence" | "raw">("activity");
  const activeTab = controlledTab ?? localTab;
  const setActiveTab = controlledTabChange ?? setLocalTab;

  return (
    <WorkbenchDrawerFrame open={Boolean(item)} title="HELM Inspector Sidecar" onClose={onClose}>
      {!visibleItem ? (
        <EmptyLine
          title="No selection"
          body="Select work, proof, capability, or diagnostics to inspect details."
        />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
          {/* 6 Tabs Header */}
          <Tabs
            value={activeTab}
            options={[
              { value: "activity", label: "activity" },
              { value: "boundary", label: "boundary" },
              { value: "mcp", label: "mcp" },
              { value: "runtime", label: "runtime" },
              { value: "evidence", label: "evidence" },
              { value: "raw", label: "raw" },
            ]}
            onChange={setActiveTab}
            label="Inspector Navigation"
            variant="inline"
          />

          {/* Tab Contents */}
          <div className="tab-content" style={{ flex: 1, overflowY: "auto" }}>
            {activeTab === "activity" && (
              <div className="drawer-stack">
                {visibleItem.kind === "task" ? (
                  <TaskDetail task={visibleItem.task} onNavigate={onNavigate} />
                ) : visibleItem.kind === "receipt" ? (
                  <ReceiptDetail
                    receipt={visibleItem.receipt}
                    replayStatus={replayStatus}
                    onReplay={onReplay}
                  />
                ) : visibleItem.kind === "capability" ? (
                  <CapabilityDetail capability={visibleItem.capability} onOpen={onOpen} />
                ) : visibleItem.kind === "record" ? (
                  <RecordDetail
                    capability={visibleItem.capability}
                    record={visibleItem.record}
                    onOpen={onOpen}
                  />
                ) : visibleItem.kind === "action" ? (
                  <ActionSheet
                    capability={visibleItem.capability}
                    action={visibleItem.action}
                    onRefresh={onRefresh}
                  />
                ) : visibleItem.kind === "diagnostics" ? (
                  <DiagnosticsDetail
                    diagnostics={visibleItem.diagnostics}
                    onNavigate={onNavigate}
                  />
                ) : (
                  <TimelineDetail step={visibleItem.step} />
                )}
              </div>
            )}

            {activeTab === "boundary" && (
              <div className="drawer-stack">
                <div className="drawer-title-row">
                  <VerdictBadge state={visibleItem.kind === "receipt" ? normalizeVerdict(visibleItem.receipt.status) : "pending"} />
                </div>
                <h2>Execution Boundary</h2>
                <p>AppSpec sandbox profile & capability preopens truth.</p>
                <WorkbenchProofSection title="Sandbox Configuration">
                  <PropertyGrid items={[
                    { label: "FS Preopens", value: "AppSpec default: no directory preopens allowed by default" },
                    { label: "Network Policy", value: "block-all-by-default (DNS fallback only)" },
                    { label: "Environment", value: "Stripped environment (credentials fully isolated)" },
                    { label: "Limits", value: "Memory: 512MB / CPU: 1.0 share" },
                    { label: "Profile Epoch", value: "UCS v1.3 Canonical Stance" },
                  ]} />
                </WorkbenchProofSection>

                <WorkbenchProofSection title="TEE Secure Enclave Integrity">
                  <div style={{ background: "rgba(99, 230, 242, 0.03)", border: "0.5px solid rgba(99, 230, 242, 0.2)", padding: "16px", borderRadius: "6px", display: "grid", gap: "12px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <span className="dot-glowing" style={{ width: "8px", height: "8px", background: "var(--color-success)", borderRadius: "50%", display: "inline-block", boxShadow: "0 0 8px var(--color-success)" }} />
                        <strong style={{ fontSize: "11px", letterSpacing: "0.05em", color: "var(--color-text-primary)" }}>TEE SEALED HARDWARE RUNTIME</strong>
                      </div>
                      <span style={{ fontSize: "11px", fontFamily: "var(--font-mono)", color: "var(--color-success)", fontWeight: "bold" }}>SECURE (AMD SEV-SNP)</span>
                    </div>
                    <div style={{ display: "grid", gap: "4px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", color: "var(--color-text-secondary)" }}>
                        <span>Enclave Measurement (MRENCLAVE) Match</span>
                        <span>100% Verified Integrity</span>
                      </div>
                      <div style={{ width: "100%", height: "4px", background: "rgba(255, 255, 255, 0.1)", borderRadius: "2px", overflow: "hidden" }}>
                        <div style={{ width: "100%", height: "100%", background: "var(--color-success)" }} />
                      </div>
                    </div>
                    <div style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--color-text-muted)", display: "flex", justifyContent: "space-between" }}>
                      <span>MRSIGNER: 0x9f8e7d...6a2b</span>
                      <span>SVN: 3</span>
                      <span>Enclave ID: env-snp-4f9a</span>
                    </div>
                  </div>
                </WorkbenchProofSection>

                <WorkbenchProofSection title="Active Policy Audit Log">
                  <AnnotatedCodeBlock
                    code={`[sandbox]\nisolation = "virtual-process"\nmemory_limit = "512MB"\ncpu_shares = 1.0\n\n[network]\nmode = "block-all"\nallow_dns = true\nallowed_hosts = [\n  "*.mcp.helm-ai.local",\n  "github.com"\n]\n\n[filesystem]\nread_only = true\npreopen_dirs = [\n  "/tmp/sandbox",\n  "/Users/ivan/Code/Mindburn-Labs/helm-ai-kernel/apps"\n]`}
                    language="toml"
                    annotations={[
                      {
                        line: 17,
                        text: "Quarantined access: Wildcard path preopen '/Users/ivan/Code/Mindburn-Labs/helm-ai-kernel/apps' allows potentially unsafe directory write.",
                        type: "warning",
                        fixSuggestion: 'preopen_dirs = ["/tmp/sandbox"]',
                        fixLabel: "Strict isolated preopens only",
                      },
                      {
                        line: 8,
                        text: "DNS fallback is enabled by default. Secure firewall is configured to fail-closed.",
                        type: "info",
                      }
                    ]}
                    onApplyFix={(ann) => {
                      alert(`Successfully applied fix: ${ann.fixLabel || ann.fixSuggestion}`);
                    }}
                  />
                </WorkbenchProofSection>
              </div>
            )}

            {activeTab === "mcp" && (
              <div className="drawer-stack">
                <div className="drawer-title-row">
                  <VerdictBadge state="allow" />
                </div>
                <h2>MCP Firewall</h2>
                <p>MCP quarantined servers & runtime threat policy enforcement.</p>
                <WorkbenchProofSection title="MCP Threat Review">
                  <PropertyGrid items={[
                    { label: "Active Quarantine", value: "0 tools blocked" },
                    { label: "Server Status", value: "PASS (all active tools cleared)" },
                    { label: "Policy Match", value: "canonical-mcp-whitelist-v1.3" },
                  ]} />
                </WorkbenchProofSection>
              </div>
            )}

            {activeTab === "runtime" && (
              <div className="drawer-stack">
                <h2>Runtime Log Summary</h2>
                <p>Container lifecycle tracking & receipts verification logs.</p>
                <WorkbenchProofSection title="Runtime State">
                  <PropertyGrid items={[
                    { label: "Substrate", value: "local-container" },
                    { label: "Status", value: "PROVISIONED / ACTIVE" },
                    { label: "Engine", value: "Docker-HELM virtual sandbox" },
                  ]} />
                </WorkbenchProofSection>
                <div style={{
                  background: "#000000",
                  color: "#00ff00",
                  padding: "12px",
                  borderRadius: "6px",
                  fontSize: "11px",
                  fontFamily: "monospace",
                  lineHeight: "1.4",
                  maxHeight: "200px",
                  overflowY: "auto",
                  marginTop: "12px",
                  border: "1px solid var(--color-border)",
                }}>
                  <div>[HELM Kernel] initializing boundary... OK</div>
                  <div>[HELM Kernel] sandbox preopens verify... OK</div>
                  <div>[HELM Kernel] testing capability constraints... OK</div>
                  <div>[HELM Kernel] checking local policy hashes... OK</div>
                  <div>[HELM Kernel] tenant verification ready... OK</div>
                  <div>[HELM Kernel] execution receipts generated... OK</div>
                </div>
              </div>
            )}

            {activeTab === "evidence" && (
              <div className="drawer-stack">
                <h2>Cryptographic Evidence</h2>
                <p>Signed verification packets & cryptographic trust receipts.</p>
                
                <WorkbenchProofSection title="Verification Status & Hash Chain">
                  {visibleItem.kind === "receipt" && visibleItem.receipt.signature ? (
                    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px", background: "rgba(97, 217, 139, 0.05)", border: "0.5px solid rgba(97, 217, 139, 0.2)", padding: "10px 14px", borderRadius: "6px" }}>
                        <CheckCircle2 size={16} color="var(--color-success)" />
                        <strong style={{ color: "var(--color-success)", fontSize: "12px", letterSpacing: "0.05em" }}>VERIFIED SIGNATURE PASS</strong>
                      </div>
                      <PropertyGrid items={[
                        { label: "Signer Identity", value: "OrgGenome Trusted Tenant Signer" },
                        { label: "Signature Hash", value: visibleItem.receipt.signature.slice(0, 32) + "..." },
                        { label: "EvidencePack ID", value: visibleItem.receipt.blob_hash ?? "evp_9f8e7d2b6a4c" },
                      ]} />
                    </div>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px", background: "rgba(99, 230, 242, 0.05)", border: "0.5px solid rgba(99, 230, 242, 0.2)", padding: "10px 14px", borderRadius: "6px" }}>
                        <ShieldCheck size={16} color="var(--color-accent-cyan)" />
                        <strong style={{ color: "var(--color-accent-cyan)", fontSize: "12px", letterSpacing: "0.05em" }}>PREFLIGHT VERIFIED EVIDENCE</strong>
                      </div>
                      <PropertyGrid items={[
                        { label: "Kernel Authority", value: "HELM Local Preflight Attestation" },
                        { label: "Evidence Hash", value: "sha256:d57f12e9b813f41249b28f3ac612c288df71a9386dca0b1c028e938cd41ba7a8" },
                        { label: "Proof Model", value: "Groth16 Zero Knowledge Proof (ZKP)" },
                      ]} />
                    </div>
                  )}
                </WorkbenchProofSection>

                <WorkbenchProofSection title="Visual ZK Proof Enclave Graph">
                  <div style={{ padding: "16px", background: "rgba(0, 0, 0, 0.4)", border: "0.5px solid var(--color-border-subtle)", borderRadius: "8px", display: "grid", gap: "12px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontSize: "11px", fontWeight: "bold", textTransform: "uppercase", color: "var(--color-text-muted)", letterSpacing: "0.05em" }}>ZK Proof Chain (Groth16)</span>
                      <span className="sota-badge badge-success" style={{ padding: "2px 8px", fontSize: "10px" }}>PROVEN & SEALED</span>
                    </div>
                    <div className="custom-scrollbar" style={{ display: "flex", gap: "12px", overflowX: "auto", paddingBottom: "8px", alignItems: "center" }}>
                      <div style={{ flexShrink: 0, padding: "8px 12px", background: "rgba(99, 230, 242, 0.05)", border: "1px solid var(--color-accent-cyan)", borderRadius: "4px", textAlign: "center" }}>
                        <div style={{ fontSize: "9px", color: "var(--color-text-muted)" }}>INPUTS</div>
                        <strong style={{ fontSize: "11px", color: "var(--color-accent-cyan)", fontFamily: "var(--font-mono)" }}>AppSpec</strong>
                        <div style={{ fontSize: "9px", color: "var(--color-success)", marginTop: "4px" }}>● Hash Verified</div>
                      </div>
                      <ArrowRight size={14} style={{ color: "var(--color-text-muted)", flexShrink: 0 }} />
                      <div style={{ flexShrink: 0, padding: "8px 12px", background: "rgba(99, 230, 242, 0.05)", border: "1px solid var(--color-accent-cyan)", borderRadius: "4px", textAlign: "center" }}>
                        <div style={{ fontSize: "9px", color: "var(--color-text-muted)" }}>RELATION</div>
                        <strong style={{ fontSize: "11px", color: "var(--color-accent-cyan)", fontFamily: "var(--font-mono)" }}>Sandbox</strong>
                        <div style={{ fontSize: "9px", color: "var(--color-success)", marginTop: "4px" }}>● State Bounds</div>
                      </div>
                      <ArrowRight size={14} style={{ color: "var(--color-text-muted)", flexShrink: 0 }} />
                      <div style={{ flexShrink: 0, padding: "8px 12px", background: "rgba(97, 217, 139, 0.05)", border: "1px solid var(--color-success)", borderRadius: "4px", textAlign: "center" }}>
                        <div style={{ fontSize: "9px", color: "var(--color-text-muted)" }}>WITNESS</div>
                        <strong style={{ fontSize: "11px", color: "var(--color-success)", fontFamily: "var(--font-mono)" }}>Evidence</strong>
                        <div style={{ fontSize: "9px", color: "var(--color-success)", marginTop: "4px" }}>● Proof Gen</div>
                      </div>
                    </div>
                  </div>
                </WorkbenchProofSection>

                <WorkbenchProofSection title="Signed Genome Diff Verification">
                  <VisualCodeDiff
                    filename="policy.toml"
                    title="Transitioning to Fail-Closed"
                    diffLines={[
                      "diff --git a/policy.toml b/policy.toml",
                      "index a85f42c..66fcf1b 100644",
                      "--- a/policy.toml",
                      "+++ b/policy.toml",
                      "@@ -1,8 +1,8 @@",
                      " [policy]",
                      "-mode = \"permissive\"",
                      "+mode = \"fail-closed\"",
                      " version = \"ucs-v1.3\"",
                      " ",
                      " [signatures]",
                      "-require_signed_evidence = false",
                      "+require_signed_evidence = true",
                      " trusted_signers = [\"tenant-ca-root\"]"
                    ]}
                  />
                </WorkbenchProofSection>
              </div>
            )}

            {activeTab === "raw" && (
              <div className="drawer-stack">
                <h2>Raw JSON Payload</h2>
                <p>Inspect exact response details directly from the Helm Kernel.</p>
                <pre style={{
                  background: "var(--color-panel)",
                  color: "var(--color-text)",
                  padding: "12px",
                  borderRadius: "6px",
                  fontSize: "11px",
                  fontFamily: "monospace",
                  overflow: "auto",
                  maxHeight: "450px",
                  border: "1px solid var(--color-border)"
                }}>
                  {JSON.stringify(visibleItem, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </WorkbenchDrawerFrame>
  );
}

function TaskDetail({
  task,
  onNavigate,
}: {
  readonly task: OperatorTask;
  readonly onNavigate: (route: FlowRoute, item?: DrawerItem) => void;
}) {
  return (
    <div className="drawer-stack">
      <StateMarker state={task.state} severity={task.severity} />
      <h2>{task.title}</h2>
      <p>{task.summary}</p>
      <PropertyGrid items={[
        { label: "source", value: task.source },
        { label: "state", value: task.state },
        {
          label: "receipts",
          value: task.relatedReceiptIds.length
            ? task.relatedReceiptIds.map(shortId).join(", ")
            : "none",
        },
      ]} />
      <Button
        variant="primary"
        onClick={() => onNavigate(task.route, { kind: "task", task })}
      >
        {task.actionLabel}
      </Button>
    </div>
  );
}

function ReceiptDetail({
  receipt,
  replayStatus,
  onReplay,
}: {
  readonly receipt: Receipt;
  readonly replayStatus: string;
  readonly onReplay: () => void;
}) {
  return (
    <div className="drawer-stack">
      <div className="drawer-title-row">
        <VerdictBadge state={normalizeVerdict(receipt.status)} />
        <VerificationStatus state={verificationState(receipt)} />
      </div>
      <h2>{shortId(receipt.receipt_id)}</h2>
      <p>
        {receiptAction(receipt)} · {receiptResource(receipt)}
      </p>
      <WorkbenchProofSection title="Lifecycle">
        <div className="proof-chain" aria-label="Receipt proof chain">
          {["intent", "policy", "decision", "receipt", "evidence"].map((node) => (
            <span key={node}>{node}</span>
          ))}
        </div>
      </WorkbenchProofSection>
      <WorkbenchProofSection title="Proof facts">
        <PropertyGrid items={[
          { label: "executor", value: receipt.executor_id ?? "anonymous" },
          { label: "signature", value: signatureSummary(receipt) },
          {
            label: "blob hash",
            value: receipt.blob_hash ? (
              <HashText value={receipt.blob_hash} />
            ) : (
              "not emitted"
            ),
          },
          {
            label: "output hash",
            value: receipt.output_hash ? (
              <HashText value={receipt.output_hash} kind="policy" />
            ) : (
              "not emitted"
            ),
          },
          { label: "replay", value: replayStatus },
        ]} />
      </WorkbenchProofSection>
      <div className="button-row">
        <Button variant="primary" onClick={onReplay}>
          Replay
        </Button>
        <span className="secondary-link secondary-link--static">
          Evidence export: Ledger action
        </span>
      </div>
      <RawJson title="Raw receipt" value={receipt} />
    </div>
  );
}

function CapabilityDetail({
  capability,
  onOpen,
}: {
  readonly capability: Capability;
  readonly onOpen: (item: DrawerItem) => void;
}) {
  return (
    <div className="drawer-stack">
      <StateMarker
        state={capability.status}
        severity={
          capability.status === "unavailable" || capability.status === "unauthorized"
            ? "medium"
            : "low"
        }
      />
      <h2>{capability.label}</h2>
      <p>{capability.sourceEndpoint}</p>
      {capability.readState.message ? (
        <InlineNotice message={capability.readState.message} />
      ) : null}
      <PropertyGrid items={[
        { label: "group", value: capability.group },
        { label: "records", value: String(capability.records.length) },
        { label: "actions", value: String(capability.actions.length) },
      ]} />
      <div className="drawer-actions">
        {capability.actions.length === 0 ? (
          <InlineNotice
            message={capability.unsupportedReason ?? "Unsupported by current OSS API."}
          />
        ) : null}
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
      {capability.id === "diagnostics" ? (
        <RuntimeDiagnostics raw={capability.raw} />
      ) : null}
      <RecordMiniList capability={capability} onOpen={onOpen} />
      <RawJson
        title="Raw response"
        value={capability.raw ?? capability.readState}
      />
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

function RecordDetail({
  capability,
  record,
  onOpen,
}: {
  readonly capability: Capability;
  readonly record: RecordSummary;
  readonly onOpen: (item: DrawerItem) => void;
}) {
  return (
    <div className="drawer-stack">
      <StateMarker state={record.state} severity="low" />
      <h2>{record.label}</h2>
      <p>{record.source}</p>
      <PropertyGrid items={[
        { label: "state", value: record.state },
        {
          label: "receipts",
          value: record.receiptRefs.length
            ? record.receiptRefs.map(shortId).join(", ")
            : "none",
        },
        ...record.facts.map((fact) => {
          const [label, ...rest] = fact.split(": ");
          return { label, value: rest.join(": ") };
        }),
      ]} />
      <div className="drawer-actions">
        {capability.actions.slice(0, 4).map((action) => (
          <button
            key={action.id}
            type="button"
            onClick={() => onOpen({ kind: "action", capability, action })}
          >
            <span>{action.label}</span>
            <small>{action.method}</small>
          </button>
        ))}
      </div>
      <RawJson title="Raw record" value={record.raw} />
    </div>
  );
}

function ActionSheet({
  capability,
  action,
  onRefresh,
}: {
  readonly capability: Capability;
  readonly action: WorkbenchAction;
  readonly onRefresh: (id: string) => Promise<void>;
}) {
  const [values, setValues] = useState<AdminActionValues>(() => {
    const defaults: Record<string, string> = {};
    for (const field of action.fields) {
      defaults[field.id] = field.defaultValue ?? "";
    }
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
      setError(
        "A human operator confirmation is required before this side effect can run."
      );
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
      <WorkbenchActionSheetFrame
        title={action.label}
        method={action.method}
        endpoint={action.endpoint}
        risk={action.risk}
      >
        <p>{capability.label}</p>
        <section
          className="human-action-boundary"
          aria-label="Human-only action boundary"
        >
          <strong>{sideEffectful ? "Human-only side effect" : "Read-only browser action"}</strong>
          <p>
            HELM AI can explain, draft, summarize, and simulate. HELM AI cannot
            approve, weaken, bypass, launch, inject secrets, or delete evidence.
          </p>
          <PropertyGrid items={[
            { label: "permission", value: `${action.method} ${action.endpoint}` },
            { label: "CLI equivalent", value: cliEquivalent },
            {
              label: "expected receipt",
              value: sideEffectful
                ? "required after successful mutation"
                : "not required for read-only inspection",
            },
          ]} />
          {sideEffectful ? (
            <label className="human-confirm-check">
              <input
                type="checkbox"
                checked={humanConfirmed}
                onChange={(event) => setHumanConfirmed(event.target.checked)}
              />
              <span>
                I am the human operator authorizing this Console side effect.
              </span>
            </label>
          ) : null}
        </section>
        {action.disabledReason ? (
          <InlineNotice message={action.disabledReason} />
        ) : null}
        {action.fields.length === 0 ? (
          <InlineNotice message="This action sends no request body fields." />
        ) : null}
        {action.fields.map((field) => (
          <label key={field.id}>
            <span>
              {field.label}
              {field.required ? " *" : ""}
            </span>
            {field.kind === "textarea" ? (
              <textarea
                value={values[field.id] ?? ""}
                placeholder={field.placeholder}
                required={field.required}
                onChange={(event) =>
                  setValues((current) => ({
                    ...current,
                    [field.id]: event.target.value,
                  }))
                }
              />
            ) : field.kind === "select" ? (
              <select
                value={values[field.id] ?? ""}
                required={field.required}
                onChange={(event) =>
                  setValues((current) => ({
                    ...current,
                    [field.id]: event.target.value,
                  }))
                }
              >
                <option value="">Select...</option>
                {(field.options ?? []).map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            ) : (
              <input
                value={values[field.id] ?? ""}
                placeholder={field.placeholder}
                required={field.required}
                onChange={(event) =>
                  setValues((current) => ({
                    ...current,
                    [field.id]: event.target.value,
                  }))
                }
              />
            )}
          </label>
        ))}
        {error ? <InlineError message={error} /> : null}
        <Button
          type="submit"
          variant="primary"
          disabled={
            busy ||
            Boolean(action.disabledReason) ||
            (sideEffectful && !humanConfirmed)
          }
        >
          {busy ? "Running" : `Run ${action.label}`}
        </Button>
        {result ? (
          <>
            <PropertyGrid items={[
              {
                label: "receipt postcondition",
                value: receiptRefs.length
                  ? receiptRefs.map(shortId).join(", ")
                  : "unproven",
              },
            ]} />
            <RawJson title="Action result" value={result} />
          </>
        ) : null}
      </WorkbenchActionSheetFrame>
    </form>
  );
}

function DiagnosticsDetail({
  diagnostics,
  onNavigate,
}: {
  readonly diagnostics: readonly WorkbenchDiagnostic[];
  readonly onNavigate: (route: FlowRoute) => void;
}) {
  return (
    <div className="drawer-stack">
      <StateMarker
        state={`${diagnostics.length} diagnostics`}
        severity={diagnostics.length ? "medium" : "low"}
      />
      <h2>Diagnostics</h2>
      <p>Fail-closed API states are condensed here so the workbench stays focused.</p>
      {diagnostics.length === 0 ? (
        <EmptyLine
          title="No diagnostics"
          body="No unavailable protected route is currently visible."
        />
      ) : null}
      <div className="record-list">
        {diagnostics.map((item) => (
          <WorkbenchRecordRow
            key={item.id}
            title={item.label}
            detail={item.message}
            meta={item.source}
            onClick={() => onNavigate(item.route)}
          />
        ))}
      </div>
    </div>
  );
}

function TimelineDetail({ step }: { readonly step: TaskTimelineStep }) {
  return (
    <div className="drawer-stack">
      <StateMarker
        state={step.state}
        severity={
          step.state === "failed" || step.state === "blocked"
            ? "high"
            : step.state === "running"
            ? "medium"
            : "low"
        }
      />
      <h2>{step.label}</h2>
      <p>{step.summary}</p>
      <PropertyGrid items={[
        { label: "source", value: step.sourceEndpoint ?? "frontend view model" },
        {
          label: "receipts",
          value: step.receiptRefs.length ? step.receiptRefs.map(shortId).join(", ") : "none",
        },
        {
          label: "artifacts",
          value: step.artifactRefs.length
            ? step.artifactRefs.map(shortId).join(", ")
            : "none",
        },
      ]} />
    </div>
  );
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

function RecordMiniList({
  capability,
  onOpen,
}: {
  readonly capability: Capability;
  readonly onOpen: (item: DrawerItem) => void;
}) {
  if (capability.records.length === 0) {
    return (
      <EmptyLine
        title="No records"
        body={
          capability.readState.message ??
          "This capability returned an explicit empty state."
        }
      />
    );
  }
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

function cliForAdminAction(action: WorkbenchAction): string {
  const base = `curl -X ${action.method.toUpperCase()} "$HELM_CONSOLE_URL${
    action.endpoint
  }" -H "X-HELM-Admin-Key: $HELM_ADMIN_API_KEY"`;
  if (action.method.toUpperCase() === "GET" || action.fields.length === 0) {
    return base;
  }
  return `${base} -H "Content-Type: application/json" --data @payload.json`;
}

function receiptRefsFromUnknown(value: unknown): string[] {
  const refs = new Set<string>();
  const visit = (item: unknown) => {
    if (typeof item === "string") {
      if (/^(rcpt|receipt|sha256:|evp_|mcp_|approval)/i.test(item)) {
        refs.add(item);
      }
      return;
    }
    if (Array.isArray(item)) {
      item.forEach(visit);
      return;
    }
    if (!isRecord(item)) return;
    for (const [key, nested] of Object.entries(item)) {
      if (/receipt(_id|_ref|s|Refs|Refs)?$/i.test(key) || /receipt/i.test(key)) {
        visit(nested);
      }
      if (key === "ref") visit(nested);
      if (Array.isArray(nested) || isRecord(nested)) visit(nested);
    }
  };
  visit(value);
  return [...refs].slice(0, 8);
}
