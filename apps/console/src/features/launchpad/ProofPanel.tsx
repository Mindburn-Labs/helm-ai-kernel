import { Clipboard, Download, ShieldCheck } from "lucide-react";
import type { LaunchpadPlanResponse, LaunchpadRun, LaunchpadRunDetail } from "./types";
import { receiptRefStrings } from "./model";

export function ProofPanel({
  plan,
  run,
  detail,
  receipts = [],
  onExport,
}: {
  readonly plan?: LaunchpadPlanResponse | null;
  readonly run?: LaunchpadRun | null;
  readonly detail?: LaunchpadRunDetail | null;
  readonly receipts?: readonly string[];
  readonly onExport?: () => void;
}) {
  const activeRun = run ?? detail?.run ?? null;
  const instance = detail?.instance;
  const receiptRefs = unique([
    ...receipts,
    ...(receiptRefStrings(activeRun?.receipt_refs) ?? []),
    ...(activeRun?.install_receipt_refs ?? []),
    ...(activeRun?.launch_receipt_refs ?? []),
    ...(activeRun?.start_receipt_refs ?? []),
    ...(activeRun?.secret_grant_refs ?? []),
    ...(activeRun?.sandbox_grant_refs ?? []),
    ...(activeRun?.mcp_refs ?? []),
    ...(activeRun?.healthcheck_receipt_refs ?? []),
    ...(activeRun?.teardown_receipt_refs ?? []),
    ...(instance?.receipts ?? []),
    ...(plan?.receipts?.map((receipt) => String(receipt.ref ?? receipt.type ?? "")).filter(Boolean) ?? []),
  ]);
  const evidenceRefs = unique([
    ...(plan?.evidence_refs ?? []),
    ...(activeRun?.evidence_pack_refs ?? []),
    ...(instance?.evidencepack_refs ?? []),
    ...(instance?.evidencepack_ref ? [instance.evidencepack_ref] : []),
  ]);
  const verifyCommand = instance?.offline_verify_command ?? activeRun?.verification_command ?? "";
  const verdict = activeRun?.kernel_verdict ?? plan?.kernel_verdict ?? instance?.verdict ?? "unproven";
  const planHash = activeRun?.plan_hash ?? plan?.plan_hash ?? instance?.launchplan_hash ?? "";

  return (
    <section className="launchpad-panel">
      <div className="panel-head">
        <div className="panel-header">
          <span>Proof</span>
          <h2>Receipts and EvidencePack</h2>
          <p>Proof is rendered from Launchpad backend refs only. Missing refs remain unproven.</p>
        </div>
        {onExport ? (
          <button className="launchpad-action" type="button" disabled={!activeRun} onClick={onExport}>
            <Download size={14} aria-hidden="true" /> Export EvidencePack
          </button>
        ) : null}
      </div>
      <dl className="launchpad-facts">
        <div><dt>Verdict</dt><dd>{verdict}</dd></div>
        <div><dt>LaunchPlan hash</dt><dd>{planHash || "unproven"}</dd></div>
        <div><dt>Receipts</dt><dd>{receiptRefs.length ? `${receiptRefs.length} ref(s)` : "unproven"}</dd></div>
        <div><dt>EvidencePack</dt><dd>{evidenceRefs.length ? evidenceRefs.at(-1) : "unproven"}</dd></div>
        <div><dt>Offline verify</dt><dd>{verifyCommand || "unproven"}</dd></div>
      </dl>
      {receiptRefs.length > 0 ? (
        <div className="receipt-list">
          {receiptRefs.slice(0, 8).map((ref) => (
            <code key={ref}>{ref}</code>
          ))}
        </div>
      ) : (
        <div className="launchpad-empty">No receipt refs returned yet.</div>
      )}
      {verifyCommand ? (
        <button className="launchpad-action" type="button" onClick={() => void navigator.clipboard?.writeText(verifyCommand)}>
          <Clipboard size={14} aria-hidden="true" /> Copy verify command
        </button>
      ) : null}
      {evidenceRefs.length > 0 ? <span className="launchpad-ready"><ShieldCheck size={13} aria-hidden="true" /> evidence ref returned</span> : null}
    </section>
  );
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}
