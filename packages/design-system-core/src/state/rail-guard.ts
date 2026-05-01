import { type HelmSemanticState, railForState } from "./semantics";

/**
 * States that REQUIRE a rail border on their containing surface
 * (Master Prompt §122 — every verdict-bearing surface ships with its rail).
 *
 * Calling `assertRailPresent` is a dev-only nudge. In production the function
 * is a no-op so it never affects runtime behavior or bundle size meaningfully.
 */
const STATES_REQUIRING_RAIL: ReadonlySet<HelmSemanticState> = new Set<HelmSemanticState>([
  "allow",
  "deny",
  "escalate",
  "verified",
  "failed",
  "denied",
  "denied_by_policy",
  "permission_denied",
  "blocked",
  "critical",
]);

function isDev(): boolean {
  if (typeof import.meta === "undefined") return false;
  const env = (import.meta as ImportMeta & { env?: Record<string, unknown> }).env;
  if (!env) return false;
  if (env["MODE"] === "test") return true;
  return env["DEV"] === true;
}

/**
 * Assert that a verdict-bearing surface includes its rail.
 *
 * Call from rail-bearing component implementations passing whether
 * the rendered DOM includes the appropriate `rail-border--*` class:
 *
 * ```tsx
 * assertRailPresent("deny", true, "ApprovalQueueItem");
 * ```
 *
 * In dev, when state requires a rail and `hasRail` is false, this logs a
 * single `console.warn` describing which rail should be present.
 * In production, this is a no-op.
 */
export function assertRailPresent(state: HelmSemanticState, hasRail: boolean, label: string): void {
  if (!isDev()) return;
  if (!STATES_REQUIRING_RAIL.has(state)) return;
  if (hasRail) return;
  const rail = railForState(state);
  console.warn(`[HELM rail-guard] ${label}: state "${state}" should render a "${rail}" rail (Master Prompt §122).`);
}

export const _RAIL_GUARD_INTERNAL = Object.freeze({
  STATES_REQUIRING_RAIL,
  isDev,
});
