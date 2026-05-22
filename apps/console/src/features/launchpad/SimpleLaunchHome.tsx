import { LaunchWizard } from "./LaunchWizard";
import type { SecretRequirement } from "./model";
import type {
  LaunchpadApp,
  LaunchpadMatrixCell,
  LaunchpadPlanResponse,
  LaunchpadRunDetail,
  LaunchpadSecretGrant,
  LaunchpadSubstrate,
  MCPThreatReview,
} from "./types";

export function SimpleLaunchHome({
  apps,
  substrates,
  matrix,
  secrets,
  threatReviews,
  selectedApp,
  selectedSubstrate,
  plan,
  detail,
  busy,
  onSelectApp,
  onSelectSubstrate,
  onPreflight,
  onLaunch,
  onBindSecret,
}: {
  readonly apps: readonly LaunchpadApp[];
  readonly substrates: readonly LaunchpadSubstrate[];
  readonly matrix: readonly LaunchpadMatrixCell[];
  readonly secrets: readonly LaunchpadSecretGrant[];
  readonly threatReviews: readonly MCPThreatReview[];
  readonly selectedApp: string;
  readonly selectedSubstrate: string;
  readonly plan: LaunchpadPlanResponse | null;
  readonly detail: LaunchpadRunDetail | null;
  readonly busy: boolean;
  readonly onSelectApp: (id: string) => void;
  readonly onSelectSubstrate: (id: string) => void;
  readonly onPreflight: (id: string) => void;
  readonly onLaunch: (id: string) => void;
  readonly onBindSecret: (requirement: SecretRequirement) => void;
}) {
  return (
    <LaunchWizard
      apps={apps}
      substrates={substrates}
      matrix={matrix}
      secrets={secrets}
      threatReviews={threatReviews}
      selectedApp={selectedApp}
      selectedSubstrate={selectedSubstrate}
      plan={plan}
      detail={detail}
      busy={busy}
      onSelectApp={onSelectApp}
      onSelectSubstrate={onSelectSubstrate}
      onPreflight={onPreflight}
      onLaunch={onLaunch}
      onBindSecret={onBindSecret}
    />
  );
}
