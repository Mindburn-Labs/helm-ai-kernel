import { type ReactNode } from "react";
import { CopilotKitProvider as CopilotKit } from "@copilotkit/react-core/v2";
import "@copilotkit/react-core/v2/styles.css";
import type { HelmAiKernelAgentState } from "./state";

export function CopilotRuntimeProvider({
  children,
  runtimeUrl,
  state,
}: {
  readonly children: ReactNode;
  readonly runtimeUrl: string;
  readonly state: HelmAiKernelAgentState | null;
}) {
  return (
    <CopilotKit
      runtimeUrl={runtimeUrl}
      credentials="include"
      properties={{
        hosting: "self-hosted",
        product: "helm-ai-kernel-console",
        agent_state: state,
      }}
      showDevConsole={false}
      a2ui={undefined}
    >
      {children}
    </CopilotKit>
  );
}
