import { AlertTriangle, Trash2 } from "lucide-react";
import type { LaunchpadRun, LaunchpadRunDetail } from "./types";
import { ProofPanel } from "./ProofPanel";

export function RunTimeline({
  runs,
  detail,
  busy,
  onOpenRun,
  onTeardown,
  onExportEvidence,
}: {
  readonly runs: readonly LaunchpadRun[];
  readonly detail: LaunchpadRunDetail | null;
  readonly busy: boolean;
  readonly onOpenRun: (id: string) => void;
  readonly onTeardown: () => void;
  readonly onExportEvidence?: () => void;
}) {
  const hasEscalation = detail?.gates.some((gate) => gate.verdict === "ESCALATE") || detail?.events.some((event) => event.verdict === "ESCALATE");
  return (
    <section className="launchpad-panel">
      <div className="panel-head">
        <div className="panel-header">
          <span>Runs</span>
          <h2>Run timeline</h2>
          <p>Run state is loaded from Launchpad runtime APIs and proof refs.</p>
        </div>
        <button type="button" className="launchpad-action" disabled={busy || !detail} onClick={onTeardown}>
          <Trash2 size={14} aria-hidden="true" /> Teardown
        </button>
      </div>
      <div className="run-list">
        {runs.map((run) => {
          const id = run.launch_id ?? run.id ?? run.run_id ?? "";
          return (
            <button key={id} type="button" onClick={() => onOpenRun(id)}>
              <strong>{run.app_id}</strong>
              <span>{run.state}</span>
              <em>{run.kernel_verdict}</em>
              <code>{run.plan_hash ?? "unproven"}</code>
            </button>
          );
        })}
      </div>
      {runs.length === 0 ? <div className="launchpad-empty">No runtime instances yet.</div> : null}
      {hasEscalation ? (
        <div className="inline-error" role="status">
          <AlertTriangle size={14} aria-hidden="true" />
          <span>At least one backend gate escalated. Open Developer Mode for the exact gate, reason code, and fix action.</span>
        </div>
      ) : null}
      {detail ? (
        <div className="timeline-list">
          {detail.events.map((event) => (
            <button key={event.id} type="button" className={`timeline-event verdict-${event.verdict.toLowerCase()}`}>
              <strong>{event.label}</strong>
              <span>{event.human_summary}</span>
              <em>{event.proof_status}</em>
            </button>
          ))}
        </div>
      ) : null}
      <ProofPanel detail={detail} onExport={onExportEvidence} />
    </section>
  );
}
