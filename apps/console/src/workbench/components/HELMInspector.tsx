import { useState, type ReactNode } from "react";
import {
  AlertCircle,
  CheckCircle2,
  Circle,
  MessageSquareText,
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
}: DetailDrawerProps) {
  const visibleItem = item ?? (fallbackReceipt ? { kind: "receipt" as const, receipt: fallbackReceipt } : null);
  return (
    <WorkbenchDrawerFrame open={Boolean(item)} title="Context" onClose={onClose}>
      {!visibleItem ? (
        <EmptyLine
          title="No selection"
          body="Select work, proof, capability, or diagnostics to inspect details."
        />
      ) : visibleItem.kind === "task" ? (
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
      <dl className="fact-grid">
        <Fact label="source" value={task.source} />
        <Fact label="state" value={task.state} />
        <Fact
          label="receipts"
          value={
            task.relatedReceiptIds.length
              ? task.relatedReceiptIds.map(shortId).join(", ")
              : "none"
          }
        />
      </dl>
      <button
        type="button"
        className="primary-action"
        onClick={() => onNavigate(task.route, { kind: "task", task })}
      >
        {task.actionLabel}
      </button>
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
        <dl className="fact-grid">
          <Fact label="executor" value={receipt.executor_id ?? "anonymous"} />
          <Fact label="signature" value={signatureSummary(receipt)} />
          <Fact
            label="blob hash"
            value={
              receipt.blob_hash ? (
                <HashText value={receipt.blob_hash} />
              ) : (
                "not emitted"
              )
            }
          />
          <Fact
            label="output hash"
            value={
              receipt.output_hash ? (
                <HashText value={receipt.output_hash} kind="policy" />
              ) : (
                "not emitted"
              )
            }
          />
          <Fact label="replay" value={replayStatus} />
        </dl>
      </WorkbenchProofSection>
      <div className="button-row">
        <button type="button" className="primary-action" onClick={onReplay}>
          Replay
        </button>
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
      <dl className="fact-grid">
        <Fact label="group" value={capability.group} />
        <Fact label="records" value={String(capability.records.length)} />
        <Fact label="actions" value={String(capability.actions.length)} />
      </dl>
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
      <dl className="fact-grid">
        <Fact label="state" value={record.state} />
        <Fact
          label="receipts"
          value={
            record.receiptRefs.length
              ? record.receiptRefs.map(shortId).join(", ")
              : "none"
          }
        />
        {record.facts.map((fact) => {
          const [label, ...rest] = fact.split(": ");
          return <Fact key={fact} label={label} value={rest.join(": ")} />;
        })}
      </dl>
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
          <dl className="fact-grid">
            <Fact label="permission" value={`${action.method} ${action.endpoint}`} />
            <Fact label="CLI equivalent" value={cliEquivalent} />
            <Fact
              label="expected receipt"
              value={
                sideEffectful
                  ? "required after successful mutation"
                  : "not required for read-only inspection"
              }
            />
          </dl>
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
        <button
          type="submit"
          className="primary-action"
          disabled={
            busy ||
            Boolean(action.disabledReason) ||
            (sideEffectful && !humanConfirmed)
          }
        >
          {busy ? "Running" : `Run ${action.label}`}
        </button>
        {result ? (
          <>
            <dl className="fact-grid">
              <Fact
                label="receipt postcondition"
                value={
                  receiptRefs.length
                    ? receiptRefs.map(shortId).join(", ")
                    : "unproven"
                }
              />
            </dl>
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
      <dl className="fact-grid">
        <Fact label="source" value={step.sourceEndpoint ?? "frontend view model"} />
        <Fact
          label="receipts"
          value={
            step.receiptRefs.length ? step.receiptRefs.map(shortId).join(", ") : "none"
          }
        />
        <Fact
          label="artifacts"
          value={
            step.artifactRefs.length
              ? step.artifactRefs.map(shortId).join(", ")
              : "none"
          }
        />
      </dl>
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
