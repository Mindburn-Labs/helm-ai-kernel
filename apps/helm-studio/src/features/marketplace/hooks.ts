import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { marketplaceApi } from './api';
import type { ConnectorState } from './types';

// ─── Query key factory ───────────────────────────────────────────────────────

const KEYS = {
  connectors: () => ['marketplace', 'connectors'] as const,
  connector: (id: string) => ['marketplace', 'connector', id] as const,
  versions: (id: string) => ['marketplace', 'versions', id] as const,
};

// ─── Queries ─────────────────────────────────────────────────────────────────

export function useMarketplaceConnectors(filters?: {
  state?: ConnectorState;
  search?: string;
}) {
  return useQuery({
    queryKey: [...KEYS.connectors(), filters],
    queryFn: () => marketplaceApi.listConnectors(filters),
  });
}

export function useMarketplaceConnector(connectorId: string) {
  return useQuery({
    queryKey: KEYS.connector(connectorId),
    enabled: Boolean(connectorId),
    queryFn: () => marketplaceApi.getConnector(connectorId),
  });
}

export function useConnectorVersions(connectorId: string) {
  return useQuery({
    queryKey: KEYS.versions(connectorId),
    enabled: Boolean(connectorId),
    queryFn: () => marketplaceApi.getConnectorVersions(connectorId),
  });
}

// ─── Mutations ───────────────────────────────────────────────────────────────

export function useInstallConnector() {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: ({
      workspaceId,
      connectorId,
      version,
    }: {
      workspaceId: string;
      connectorId: string;
      version: string;
    }) => marketplaceApi.installConnector(workspaceId, connectorId, version),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: KEYS.connectors() });
    },
  });
}
