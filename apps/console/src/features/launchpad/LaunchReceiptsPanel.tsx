import type { LaunchpadPlanResponse, LaunchpadRun } from "./types";

export function LaunchReceiptsPanel({ plan, run }: { plan: LaunchpadPlanResponse | null; run: LaunchpadRun | null }) {
  const receipts = (run?.receipt_refs ?? plan?.receipts ?? []).map((receipt) => ({
    type: String(receipt.type ?? "receipt"),
    ref: String(receipt.ref ?? "unproven"),
  }));
  const evidence = (run?.evidence_pack_refs ?? plan?.evidence_refs ?? []).map((ref) => String(ref));
  return (
    <section className="launchpad-panel">
      <div className="panel-header">
        <div>
          <span className="panel-kicker">evidence</span>
          <h2>Receipts and EvidencePacks</h2>
        </div>
      </div>
      <ul className="launchpad-list">
        {receipts.map((receipt) => (
          <li key={`${receipt.type}:${receipt.ref}`}>
            <span>{receipt.type}</span>
            <code>{receipt.ref}</code>
          </li>
        ))}
        {evidence.map((ref) => (
          <li key={ref}>
            <span>evidence</span>
            <code>{ref}</code>
          </li>
        ))}
      </ul>
      {receipts.length === 0 && evidence.length === 0 ? (
        <div className="launchpad-empty" role="status">Plan or launch an app to emit receipt and EvidencePack references.</div>
      ) : null}
    </section>
  );
}
