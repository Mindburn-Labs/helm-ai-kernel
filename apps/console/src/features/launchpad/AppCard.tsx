import { AlertTriangle, CheckCircle2, Play } from "lucide-react";
import { DeveloperModePanel } from "./DeveloperModePanel";
import { EntitlementGate } from "./EntitlementGate";
import {
  appKey,
  entitlementAllows,
  entitlementReason,
  isFixtureOnly,
  launchBlockedReasons,
  sandboxSummary,
  secretRequirements,
  type SecretRequirement,
} from "./model";
import type { LaunchpadApp, LaunchpadMatrixCell, LaunchpadSecretGrant, LaunchpadSubstrate, MCPThreatReview } from "./types";

export function AppCard({
  app,
  selected,
  substrate,
  cell,
  secrets,
  reviews,
  busy,
  onSelect,
  onPreflight,
  onLaunch,
  onBindSecret,
}: {
  readonly app: LaunchpadApp;
  readonly selected: boolean;
  readonly substrate?: LaunchpadSubstrate;
  readonly cell?: LaunchpadMatrixCell;
  readonly secrets: readonly LaunchpadSecretGrant[];
  readonly reviews: readonly MCPThreatReview[];
  readonly busy: boolean;
  readonly onSelect: (id: string) => void;
  readonly onPreflight: (id: string) => void;
  readonly onLaunch: (id: string) => void;
  readonly onBindSecret: (requirement: SecretRequirement) => void;
}) {
  const id = appKey(app);
  const requirements = secretRequirements(app, secrets);
  const missing = requirements.filter((requirement) => {
    return !requirement.present || app.status?.missing_secrets?.includes(requirement.env) || app.status?.missing_secrets?.includes(requirement.logical);
  });
  const blockedReasons = launchBlockedReasons(app, cell, missing, reviews);
  const launchAllowedByEntitlement = entitlementAllows(app, "launch");
  const launchReason = entitlementReason(app, "launch");
  const canLaunch = blockedReasons.length === 0 && Boolean(substrate?.id) && launchAllowedByEntitlement;
  const state = app.user_state ?? stateFromBackend(app, missing, reviews, cell);
  const decision = app.action_states?.launch ?? app.entitlement_decision;

  return (
    <article className={`appspec-card status-${app.status?.state ?? state}`}>
      <button type="button" className="appspec-main" aria-pressed={selected} onClick={() => onSelect(id)}>
        <span className="appspec-title-row">
          <strong>{app.name}</strong>
          <StateBadge state={state} fixtureOnly={isFixtureOnly(app, "launch")} />
        </span>
        <code>{app.oci_ref ?? app.immutable_digest ?? "artifact unproven"}</code>
        <span>{app.status?.summary ?? app.blocked_reason ?? stateLabel(state)}</span>
      </button>
      <dl className="launchpad-facts">
        <Fact label="Status" value={app.status?.state ?? state} />
        <Fact label="Matrix" value={cell ? `${cell.verdict} - ${cell.reason}` : "unproven"} />
        <Fact label="Policy" value={app.policy_ref ?? "unproven"} />
        <Fact label="Secrets" value={`${requirements.length} required, ${missing.length} missing`} />
        <Fact label="MCP" value={`${app.mcp_servers?.length ?? 0} declared, ${reviews.length} reviewed`} />
        <Fact label="Filesystem" value={app.filesystem_needs?.join(", ") || "deny by default"} />
        <Fact label="Network" value={app.network_needs?.join(", ") || "deny by default"} />
        <Fact label="Model env" value={app.model_gateway_env?.join(", ") || "none"} />
        <Fact label="Sandbox" value={sandboxSummary(app)} />
        <Fact label="EvidencePack" value={app.status?.last_evidence_pack ? "available" : "unproven"} />
      </dl>
      {missing.length > 0 ? <SecretSetupPanel requirements={missing} busy={busy} onBindSecret={onBindSecret} /> : null}
      {blockedReasons.length > 0 ? <InlineBlock title="Launch blocked" items={blockedReasons} /> : null}
      {launchReason && !launchAllowedByEntitlement ? <InlineBlock title="Access decision" items={[launchReason]} /> : null}
      <div className="cli-equivalent">Preflight CLI: helm app preflight {id}{substrate?.id ? ` --substrate ${substrate.id}` : ""}</div>
      <div className="cli-equivalent">Launch CLI: helm app run {id}{substrate?.id ? ` --substrate ${substrate.id}` : ""}</div>
      <div className="launchpad-actions">
        <button type="button" className="launchpad-action" disabled={busy || !substrate?.id} onClick={() => onPreflight(id)}>Preflight</button>
        <EntitlementGate decision={decision}>
          <button
            type="button"
            className="launchpad-action launchpad-action-primary"
            disabled={busy || !canLaunch}
            title={!canLaunch ? blockedReasons[0] ?? launchReason ?? "Launch is not available." : undefined}
            onClick={() => onLaunch(id)}
          >
            <Play size={14} aria-hidden="true" /> Launch
          </button>
        </EntitlementGate>
      </div>
      {selected ? <span className="launchpad-ready"><CheckCircle2 size={13} aria-hidden="true" /> selected</span> : null}
      {selected ? <DeveloperModePanel title="Developer facts" raw={{ app, matrix_cell: cell, secret_requirements: requirements, mcp_reviews: reviews }} /> : null}
    </article>
  );
}

function SecretSetupPanel({
  requirements,
  busy,
  onBindSecret,
}: {
  readonly requirements: readonly SecretRequirement[];
  readonly busy: boolean;
  readonly onBindSecret: (requirement: SecretRequirement) => void;
}) {
  return (
    <div className="secret-fix-panel">
      <strong>Missing secret blocks launch</strong>
      <p>Set the named environment variable in the Kernel process, then bind that env name. The Console does not collect raw secret values.</p>
      {requirements.map((requirement) => (
        <div key={`${requirement.logical}:${requirement.env}`} className="secret-fix-row">
          <code>{requirement.cli}</code>
          <button type="button" className="launchpad-action" disabled={busy} onClick={() => onBindSecret(requirement)}>
            Bind env
          </button>
        </div>
      ))}
    </div>
  );
}

function StateBadge({ state, fixtureOnly }: { readonly state: string; readonly fixtureOnly: boolean }) {
  const normalized = state.toLowerCase();
  const tone = normalized.includes("available") || normalized.includes("ready") ? "success" : normalized.includes("needs") || normalized.includes("review") ? "warning" : "danger";
  return <span className={`sota-badge badge-${tone}`}>{fixtureOnly ? "FIXTURE " : ""}{stateLabel(state).toUpperCase()}</span>;
}

function stateFromBackend(
  app: LaunchpadApp,
  missing: readonly SecretRequirement[],
  reviews: readonly MCPThreatReview[],
  cell?: LaunchpadMatrixCell,
): string {
  if (app.status?.state) return app.status.state;
  if (missing.length > 0) return "needs_setup";
  if (reviews.some((review) => review.state === "quarantined")) return "mcp_review";
  if (!cell || !cell.launchable || cell.verdict !== "ALLOW") return "blocked";
  if (app.availability && app.availability !== "oss_supported") return "unsupported";
  return "available";
}

function stateLabel(state: string): string {
  return state.replace(/_/g, " ");
}

function InlineBlock({ title, items }: { readonly title: string; readonly items: readonly string[] }) {
  return (
    <div className="inline-error" role="status">
      <AlertTriangle size={14} aria-hidden="true" />
      <span><strong>{title}</strong>: {items.join(" ")}</span>
    </div>
  );
}

function Fact({ label, value }: { readonly label: string; readonly value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}
