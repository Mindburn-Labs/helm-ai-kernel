import { createContext, useContext, type ReactNode } from "react";
import { CopilotKit } from "@copilotkit/react-core";
import type { HelmAiKernelAgentState } from "./state";

interface AiKernelAgentProviderValue {
  readonly runtimeUrl: string;
  readonly state: HelmAiKernelAgentState | null;
}

const AiKernelAgentContext = createContext<AiKernelAgentProviderValue>({
  runtimeUrl: "/api/v1/agent-ui",
  state: null,
});

export function HelmAiKernelAgentProvider({
  children,
  state = null,
  runtimeUrl = "/api/v1/agent-ui",
}: {
  readonly children: ReactNode;
  readonly state?: HelmAiKernelAgentState | null;
  readonly runtimeUrl?: string;
}) {
  return (
    <AiKernelAgentContext.Provider value={{ runtimeUrl, state }}>
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
    </AiKernelAgentContext.Provider>
  );
}

export function useHelmAiKernelAgentProvider() {
  return useContext(AiKernelAgentContext);
}
