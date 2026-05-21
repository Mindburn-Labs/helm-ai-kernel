import type { LaunchpadApp, LaunchpadSubstrate } from "./types";

export function PolicyPackPanel({ app, substrate }: { app?: LaunchpadApp; substrate?: LaunchpadSubstrate }) {
  return (
    <section className="launchpad-panel">
      <div className="panel-header">
        <div>
          <span className="panel-kicker">policy</span>
          <h2>Pack posture</h2>
        </div>
      </div>
      <dl className="launchpad-facts">
        <div><dt>app</dt><dd>{app?.blocked_reason || app?.availability || "unavailable"}</dd></div>
        <div><dt>substrate</dt><dd>{substrate?.blocked_reason || substrate?.availability || "unavailable"}</dd></div>
        <div><dt>install</dt><dd>{app?.install_strategy || "not returned"}</dd></div>
      </dl>
    </section>
  );
}
