import { createContext, useContext, useEffect, useState, type ComponentType, type ReactNode } from "react";
import type { HelmAiKernelAgentState } from "./state";

interface AiKernelAgentProviderValue {
  readonly runtimeUrl: string;
  readonly state: HelmAiKernelAgentState | null;
}

interface CopilotRuntimeProviderProps extends AiKernelAgentProviderValue {
  readonly children: ReactNode;
}

const AiKernelAgentContext = createContext<AiKernelAgentProviderValue>({
  runtimeUrl: "/api/v1/agent-ui",
  state: null,
});

export const helmCopilotKitBuildEnabled = import.meta.env.VITE_HELM_CONSOLE_COPILOTKIT_ENABLED === "true";

export function HelmAiKernelAgentProvider({
  children,
  enabled = false,
  state = null,
  runtimeUrl = "/api/v1/agent-ui",
}: {
  readonly children: ReactNode;
  readonly enabled?: boolean;
  readonly state?: HelmAiKernelAgentState | null;
  readonly runtimeUrl?: string;
}) {
  const [CopilotRuntimeProvider, setCopilotRuntimeProvider] = useState<ComponentType<CopilotRuntimeProviderProps> | null>(null);

  useEffect(() => {
    if (!enabled || !helmCopilotKitBuildEnabled) return undefined;
    let cancelled = false;
    void import("./copilot-provider").then((module) => {
      if (!cancelled) setCopilotRuntimeProvider(() => module.CopilotRuntimeProvider);
    });
    return () => {
      cancelled = true;
    };
  }, [enabled]);

  if (!enabled || !helmCopilotKitBuildEnabled || !CopilotRuntimeProvider) {
    return (
      <AiKernelAgentContext.Provider value={{ runtimeUrl, state }}>
        {children}
      </AiKernelAgentContext.Provider>
    );
  }

  return (
    <AiKernelAgentContext.Provider value={{ runtimeUrl, state }}>
      <CopilotRuntimeProvider runtimeUrl={runtimeUrl} state={state}>
        {children}
      </CopilotRuntimeProvider>
    </AiKernelAgentContext.Provider>
  );
}

export function useHelmAiKernelAgentProvider() {
  return useContext(AiKernelAgentContext);
}
