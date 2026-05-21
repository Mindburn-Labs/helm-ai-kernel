export function McpQuarantinePanel() {
  return (
    <section className="launchpad-panel">
      <div className="panel-header">
        <div>
          <span className="panel-kicker">mcp</span>
          <h2>Quarantine default</h2>
        </div>
      </div>
      <dl className="launchpad-facts">
        <div><dt>unknown server</dt><dd>quarantine</dd></div>
        <div><dt>unknown tool</dt><dd>quarantine; no dispatch</dd></div>
        <div><dt>schema pin</dt><dd>required</dd></div>
      </dl>
    </section>
  );
}
