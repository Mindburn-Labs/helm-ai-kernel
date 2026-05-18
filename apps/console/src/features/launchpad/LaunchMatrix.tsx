import type { LaunchpadMatrixCell } from "./types";

export function LaunchMatrix({ matrix }: { matrix: LaunchpadMatrixCell[] }) {
  return (
    <section className="launchpad-panel">
      <div className="panel-head">
        <div>
          <span className="eyebrow">matrix</span>
          <h2>App and substrate cells</h2>
        </div>
      </div>
      <div className="launchpad-table" role="table" aria-label="Launchpad matrix">
        {matrix.map((cell) => (
          <div key={`${cell.app_id}:${cell.substrate_id}`} className="launchpad-row" role="row">
            <strong>{cell.app_id}</strong>
            <span>{cell.substrate_id}</span>
            <span className={`launchpad-verdict verdict-${cell.verdict.toLowerCase()}`}>{cell.verdict}</span>
            <span>{cell.launchable ? "launchable" : "blocked"}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
