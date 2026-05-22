import type {
  LaunchpadApp,
  LaunchpadMatrixCell,
  LaunchpadRun,
  LaunchpadSecretGrant,
  MCPThreatReview,
} from "./types";

export type SecretRequirement = {
  logical: string;
  env: string;
  present: boolean;
  cli: string;
  grant?: LaunchpadSecretGrant;
};

export function appKey(app: LaunchpadApp): string {
  return app.app_id ?? app.id;
}

export function secretRequirements(app: LaunchpadApp, secrets: readonly LaunchpadSecretGrant[]): SecretRequirement[] {
  const logicalNames = app.required_secrets?.length ? app.required_secrets : app.model_gateway_env ?? [];
  const envNames = app.model_gateway_env?.length ? app.model_gateway_env : logicalNames;
  return logicalNames.map((logical, index) => {
    const env = envNames[Math.min(index, envNames.length - 1)] ?? logical;
    const grant = secrets.find((secret) => secret.name === logical || secret.name === env || secret.value_env === env);
    const present = Boolean(grant?.present);
    return {
      logical,
      env,
      present,
      grant,
      cli: `helm secret set ${logical} --provider env --value-env ${env}`,
    };
  });
}

export function launchBlockedReasons(
  app: LaunchpadApp,
  cell: LaunchpadMatrixCell | undefined,
  missing: readonly SecretRequirement[],
  reviews: readonly MCPThreatReview[],
): string[] {
  const reasons: string[] = [];
  if ((app.status?.verdict ?? "ESCALATE") !== "ALLOW") reasons.push(app.status?.summary ?? app.blocked_reason ?? "App status is not ALLOW.");
  if (!cell) reasons.push("Compatibility matrix cell is unproven.");
  if (cell && (!cell.launchable || cell.verdict !== "ALLOW")) reasons.push(cell.reason || "Compatibility matrix blocks launch.");
  if (missing.length > 0) reasons.push(`Missing secret: ${missing.map((item) => `${item.logical} from ${item.env}`).join(", ")}.`);
  const confusingMcp = reviews.filter((review) => !["approved", "quarantined"].includes(review.state));
  if (confusingMcp.length > 0) reasons.push(`MCP state is not approved or quarantined: ${confusingMcp.map((review) => review.server_id).join(", ")}.`);
  if (app.user_state && ["upgrade_required", "enterprise_controlled", "blocked", "unsupported"].includes(app.user_state)) {
    reasons.push(app.upgrade_reason ?? app.entitlement_decision?.reason ?? app.entitlement_decision?.upgrade_reason ?? `App state is ${app.user_state}.`);
  }
  return uniqueStrings(reasons);
}

export function sandboxSummary(app: LaunchpadApp): string {
  const limits = app.declared_capabilities?.join(", ") || "AppSpec grant only";
  return `${limits}; no runtime without receipt`;
}

export function entitlementAllows(app: LaunchpadApp, action: string): boolean {
  const decision = app.action_states?.[action] ?? app.entitlement_decision;
  return decision?.allowed !== false;
}

export function entitlementReason(app: LaunchpadApp, action: string): string | undefined {
  const decision = app.action_states?.[action] ?? app.entitlement_decision;
  return decision?.reason ?? decision?.upgrade_reason ?? app.upgrade_reason;
}

export function isFixtureOnly(app: LaunchpadApp, action: string): boolean {
  const decision = app.action_states?.[action] ?? app.entitlement_decision;
  return Boolean(decision?.fixture_only);
}

export function receiptRefStrings(refs: LaunchpadRun["receipt_refs"] | undefined): string[] | undefined {
  if (!refs) return undefined;
  return refs.map((ref) => {
    if (typeof ref === "string") return ref;
    const value = (ref as { ref?: unknown }).ref;
    return typeof value === "string" ? value : "";
  }).filter(Boolean);
}

export function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}
