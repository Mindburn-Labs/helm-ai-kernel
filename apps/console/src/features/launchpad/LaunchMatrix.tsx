import type { LaunchpadMatrixCell } from "./types";

export function LaunchMatrix({ matrix, loading }: { matrix: LaunchpadMatrixCell[]; loading?: boolean }) {
  return (
    <section className="launchpad-panel">
      <div className="panel-header">
        <div>
          <span className="panel-kicker">matrix</span>
          <h2>App and substrate cells</h2>
        </div>
        <span className="launchpad-count">{loading ? "loading" : `${matrix.length} cells`}</span>
      </div>
      {loading && matrix.length === 0 ? (
        <div className="launchpad-skeleton" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
      ) : matrix.length === 0 ? (
        <div className="launchpad-empty" role="status">
          No app/substrate cells returned by the Launchpad API.
        </div>
      ) : (
        <div className="launchpad-table" role="table" aria-label="Launchpad matrix">
          <div className="launchpad-row launchpad-row--head" role="row">
            <span role="columnheader">app</span>
            <span role="columnheader">substrate</span>
            <span role="columnheader">verdict</span>
            <span role="columnheader">state</span>
          </div>
          {matrix.map((cell) => (
            <div key={`${cell.app_id}:${cell.substrate_id}`} className="launchpad-row" role="row">
              <strong role="cell" data-label="app">{cell.app_id}</strong>
              <span role="cell" data-label="substrate">{cell.substrate_id}</span>
              <span role="cell" data-label="verdict" className={`launchpad-verdict verdict-${cell.verdict.toLowerCase()}`}>{cell.verdict}</span>
              <span role="cell" data-label="state">{cell.launchable ? "launchable" : "blocked"}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
