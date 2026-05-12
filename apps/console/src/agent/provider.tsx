import { createContext, useContext, type ReactNode } from "react";
import { CopilotKit } from "@copilotkit/react-core";
import type { HelmOssAgentState } from "./state";

interface OssAgentProviderValue {
  readonly runtimeUrl: string;
  readonly state: HelmOssAgentState | null;
}

const OssAgentContext = createContext<OssAgentProviderValue>({
  runtimeUrl: "/api/v1/agent-ui",
  state: null,
});

export function HelmOssAgentProvider({
  children,
  state = null,
  runtimeUrl = "/api/v1/agent-ui",
}: {
  readonly children: ReactNode;
  readonly state?: HelmOssAgentState | null;
  readonly runtimeUrl?: string;
}) {
  return (
    <OssAgentContext.Provider value={{ runtimeUrl, state }}>
      <CopilotKit
        runtimeUrl={runtimeUrl}
        credentials="include"
        properties={{
          hosting: "self-hosted",
          product: "helm-oss-console",
          agent_state: state,
        }}
        showDevConsole={false}
        a2ui={undefined}
      >
        {children}
      </CopilotKit>
    </OssAgentContext.Provider>
  );
}

export function useHelmOssAgentProvider() {
  return useContext(OssAgentContext);
}
