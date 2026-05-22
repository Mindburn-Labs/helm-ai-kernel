import { Lock } from "lucide-react";
import type { ReactNode } from "react";
import type { LaunchpadEntitlementDecision } from "./types";

export function EntitlementGate({
  decision,
  children,
}: {
  readonly decision?: LaunchpadEntitlementDecision;
  readonly children: ReactNode;
}) {
  if (!decision || decision.allowed !== false) {
    return <>{children}</>;
  }
  return (
    <>
      {children}
      <div className="inline-error" role="status">
        <Lock size={14} aria-hidden="true" />
        <span>
          {decision.reason ?? decision.upgrade_reason ?? "This action is not available for the current account state."}
          {decision.fixture_only ? " Fixture-only entitlement state." : ""}
        </span>
      </div>
    </>
  );
}
