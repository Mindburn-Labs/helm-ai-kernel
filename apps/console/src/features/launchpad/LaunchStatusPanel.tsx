import type { LaunchpadPlanResponse, LaunchpadRun } from "./types";

export function LaunchStatusPanel({ plan, run }: { plan: LaunchpadPlanResponse | null; run: LaunchpadRun | null }) {
  const state = run?.state ?? plan?.state ?? "PLANNED";
  const verdict = run?.kernel_verdict ?? plan?.kernel_verdict ?? "ESCALATE";
  return (
    <section className="launchpad-panel">
      <div className="panel-header">
        <div>
          <span className="panel-kicker">status</span>
          <h2>{state}</h2>
        </div>
        <span className={`launchpad-verdict verdict-${verdict.toLowerCase()}`}>{verdict}</span>
      </div>
      <dl className="launchpad-facts">
        <div><dt>launch id</dt><dd>{run?.launch_id ?? run?.id ?? plan?.launch_id ?? "not planned"}</dd></div>
        <div><dt>plan hash</dt><dd>{run?.plan_hash ?? plan?.plan_hash ?? "not emitted"}</dd></div>
        <div><dt>reason</dt><dd>{run?.reason ?? plan?.reason ?? "waiting for API state"}</dd></div>
      </dl>
    </section>
  );
}
