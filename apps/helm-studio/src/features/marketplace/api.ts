// Feature-scoped API client for the marketplace feature.
// Uses requestJson / asJsonBody for org-scoped marketplace connector endpoints.
import { asJsonBody, requestJson } from '../../api/http';
import type { ConnectorState, ConnectorVersion, MarketplaceConnector } from './types';

export const marketplaceApi = {
  listConnectors(params?: {
    state?: ConnectorState;
    search?: string;
  }): Promise<{ connectors: MarketplaceConnector[]; count: number }> {
    const qs = new URLSearchParams();
    if (params?.state) qs.set('state', params.state);
    if (params?.search) qs.set('search', params.search);
    const query = qs.toString();
    return requestJson(`/api/v1/marketplace/connectors${query ? `?${query}` : ''}`);
  },

  getConnector(connectorId: string): Promise<MarketplaceConnector> {
    return requestJson(`/api/v1/marketplace/connectors/${connectorId}`);
  },

  getConnectorVersions(connectorId: string): Promise<{ versions: ConnectorVersion[] }> {
    return requestJson(`/api/v1/marketplace/connectors/${connectorId}/versions`);
  },

  installConnector(workspaceId: string, connectorId: string, version: string): Promise<void> {
    return requestJson(
      `/api/v1/marketplace/connectors/${connectorId}/install`,
      asJsonBody({ workspace_id: workspaceId, version }),
    );
  },
};
