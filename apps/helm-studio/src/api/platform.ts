import { controlplaneApi } from "./controlplane";

// Post-Phase-5: studio.ts is deleted — controlplane is the single backend
// namespace. All Studio-scoped methods (runs, approvals, policies,
// simulations, exports, replays, tasks, verify) now live on controlplaneApi
// alongside the existing platform/research/goal methods.
export const platform = {
  controlplane: controlplaneApi,
} as const;

export type PlatformApi = typeof platform;
