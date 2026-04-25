import { controlplaneApi } from "./controlplane";
import { studioApi } from "./studio";

export const platform = {
  studio: studioApi,
  controlplane: controlplaneApi,
} as const;

export type PlatformApi = typeof platform;
