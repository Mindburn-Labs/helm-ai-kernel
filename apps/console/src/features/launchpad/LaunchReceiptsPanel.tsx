import type { LaunchpadPlanResponse, LaunchpadRun } from "./types";

export function LaunchReceiptsPanel({ plan, run }: { plan: LaunchpadPlanResponse | null; run: LaunchpadRun | null }) {
  const receipts = run?.receipt_refs ?? plan?.receipts ?? [];
  const evidence = run?.evidence_pack_refs ?? plan?.evidence_refs ?? [];
  return (
    <section className="launchpad-panel">
      <div className="panel-head">
        <div>
          <span className="eyebrow">evidence</span>
          <h2>Receipts and EvidencePacks</h2>
        </div>
      </div>
      <ul className="launchpad-list">
        {receipts.map((receipt) => <li key={`${receipt.type}:${receipt.ref}`}>{receipt.type}: {receipt.ref}</li>)}
        {evidence.map((ref) => <li key={ref}>evidence: {ref}</li>)}
        {receipts.length === 0 && evidence.length === 0 ? <li>no proof refs returned</li> : null}
      </ul>
    </section>
  );
}
