import type { LaunchpadApp, LaunchpadSubstrate } from "./types";

export function GrantReviewPanel({ app, substrate }: { app?: LaunchpadApp; substrate?: LaunchpadSubstrate }) {
  return (
    <section className="launchpad-panel">
      <div className="panel-header">
        <div>
          <span className="panel-kicker">grants</span>
          <h2>Secrets, filesystem, network</h2>
        </div>
      </div>
      <dl className="launchpad-facts">
        <div><dt>required secrets</dt><dd>{app?.required_secrets?.join(", ") || "none returned"}</dd></div>
        <div><dt>filesystem</dt><dd>scoped workspace rw only</dd></div>
        <div><dt>network</dt><dd>{substrate?.default_dry_run ? "dry-run only" : "deny by default"}</dd></div>
      </dl>
    </section>
  );
}
