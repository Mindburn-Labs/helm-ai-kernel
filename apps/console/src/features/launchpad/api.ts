import type {
  LaunchpadApp,
  LaunchpadMatrixCell,
  LaunchpadPlanResponse,
  LaunchpadRun,
  LaunchpadSubstrate,
} from "./types";

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: "include",
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(body || `${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
}

export const launchpadApi = {
  async apps(): Promise<LaunchpadApp[]> {
    const body = await requestJson<{ apps: LaunchpadApp[] }>("/api/v1/launchpad/apps");
    return body.apps;
  },
  async substrates(): Promise<LaunchpadSubstrate[]> {
    const body = await requestJson<{ substrates: LaunchpadSubstrate[] }>("/api/v1/launchpad/substrates");
    return body.substrates;
  },
  async matrix(): Promise<LaunchpadMatrixCell[]> {
    const body = await requestJson<{ matrix: LaunchpadMatrixCell[] }>("/api/v1/launchpad/matrix");
    return body.matrix;
  },
  plan(appId: string, substrateId: string): Promise<LaunchpadPlanResponse> {
    return requestJson("/api/v1/launchpad/plan", {
      method: "POST",
      body: JSON.stringify({ app_id: appId, substrate_id: substrateId, principal: "console" }),
    });
  },
  launch(appId: string, substrateId: string): Promise<LaunchpadRun> {
    return requestJson("/api/v1/launchpad/launch", {
      method: "POST",
      body: JSON.stringify({ app_id: appId, substrate_id: substrateId, principal: "console" }),
    });
  },
  repair(launchId: string): Promise<unknown> {
    return requestJson(`/api/v1/launchpad/launches/${launchId}/repair`, { method: "POST" });
  },
  delete(launchId: string): Promise<LaunchpadRun> {
    return requestJson(`/api/v1/launchpad/launches/${launchId}/delete`, {
      method: "POST",
      body: JSON.stringify({ cascade: true }),
    });
  },
};
