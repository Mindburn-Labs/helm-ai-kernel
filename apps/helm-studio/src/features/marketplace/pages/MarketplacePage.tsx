import { useOperatorShell } from '../../../operator/layout';
import {
  EmptyState,
  ErrorState,
  LoadingState,
  SurfaceIntro,
  TopStatusPill,
} from '../../../operator/components';
import { useMarketplaceConnectors, useInstallConnector } from '../hooks';
import { useMarketplaceStore } from '../store';
import { ConnectorCatalog } from '../components/ConnectorCatalog';
import { CertificationBadgeStrip } from '../components/CertificationBadgeStrip';
import { VersionHistoryPanel } from '../components/VersionHistoryPanel';
import type { ConnectorState } from '../types';

export function MarketplacePage() {
  const shell = useOperatorShell();
  const store = useMarketplaceStore();

  const { data, isLoading, isError, error, refetch } = useMarketplaceConnectors({
    state: store.filterState ?? undefined,
    search: store.searchQuery || undefined,
  });

  const installMutation = useInstallConnector();

  const connectors = data?.connectors ?? [];
  const selectedConnector = connectors.find((c) => c.id === store.selectedConnectorId) ?? null;

  if (isLoading) {
    return <LoadingState label="Loading marketplace connectors..." />;
  }

  if (isError) {
    return (
      <ErrorState
        error={error}
        retry={() => void refetch()}
        title="Could not load marketplace"
      />
    );
  }

  const certifiedCount = connectors.filter((c) => c.state === 'certified').length;
  const candidateCount = connectors.filter((c) => c.state === 'candidate').length;
  const revokedCount = connectors.filter((c) => c.state === 'revoked').length;

  return (
    <div className="operator-surface-page">
      <SurfaceIntro
        eyebrow="Marketplace"
        title="Connector Marketplace"
        description="Browse certified connectors and candidates. Install connectors to unlock new AI agent capabilities in your workspace."
        actions={
          <div className="operator-rail-status">
            <TopStatusPill label="Certified" tone="success" value={String(certifiedCount)} />
            <TopStatusPill label="Candidate" tone="info" value={String(candidateCount)} />
            <TopStatusPill
              label="Revoked"
              tone={revokedCount > 0 ? 'danger' : 'neutral'}
              value={String(revokedCount)}
            />
          </div>
        }
      />

      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '0 0 12px' }}>
        <input
          placeholder="Search connectors..."
          style={{
            fontSize: '12px',
            padding: '6px 10px',
            borderRadius: '6px',
            border: '1px solid rgba(158, 178, 198, 0.2)',
            background: 'rgba(0, 0, 0, 0.2)',
            color: 'var(--operator-text)',
            minWidth: '200px',
          }}
          type="search"
          value={store.searchQuery}
          onChange={(e) => store.setSearchQuery(e.target.value)}
        />

        <select
          onChange={(e) => store.setFilterState((e.target.value || null) as ConnectorState | null)}
          style={{ fontSize: '12px' }}
          value={store.filterState ?? ''}
        >
          <option value="">All states</option>
          <option value="certified">Certified</option>
          <option value="candidate">Candidate</option>
          <option value="revoked">Revoked</option>
        </select>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 320px',
          gap: '20px',
          minHeight: '400px',
        }}
      >
        {/* Left: connector catalog */}
        <div>
          {connectors.length === 0 ? (
            <EmptyState
              title="No connectors found"
              body="No connectors match the current filters. Try adjusting your search or state filter."
            />
          ) : (
            <ConnectorCatalog
              connectors={connectors}
              selectedId={store.selectedConnectorId}
              onSelect={store.setSelectedConnector}
            />
          )}
        </div>

        {/* Right: connector detail */}
        <div
          style={{
            borderLeft: '1px solid rgba(158, 178, 198, 0.1)',
            paddingLeft: '20px',
            display: 'flex',
            flexDirection: 'column',
            gap: '14px',
          }}
        >
          {selectedConnector ? (
            <>
              <div>
                <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--operator-text)', margin: 0 }}>
                  {selectedConnector.name}
                </h3>
                <p style={{ fontSize: '12px', color: 'var(--operator-text-muted)', margin: '4px 0 0' }}>
                  v{selectedConnector.version}
                </p>
              </div>

              <CertificationBadgeStrip connector={selectedConnector} />
              <VersionHistoryPanel connectorId={selectedConnector.id} />

              {selectedConnector.state === 'certified' ? (
                <button
                  className="operator-button primary"
                  disabled={installMutation.isPending}
                  onClick={() =>
                    void installMutation.mutate({
                      workspaceId: shell.workspaceId,
                      connectorId: selectedConnector.id,
                      version: selectedConnector.version,
                    })
                  }
                  type="button"
                >
                  {installMutation.isPending ? 'Installing…' : 'Install connector'}
                </button>
              ) : null}

              {installMutation.isSuccess ? (
                <p style={{ fontSize: '12px', color: 'rgba(80, 220, 120, 0.9)', margin: 0 }}>
                  Connector installed successfully.
                </p>
              ) : null}

              {installMutation.isError ? (
                <p style={{ fontSize: '12px', color: 'var(--operator-tone-danger)', margin: 0 }}>
                  {installMutation.error instanceof Error
                    ? installMutation.error.message
                    : 'Installation failed.'}
                </p>
              ) : null}
            </>
          ) : (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: 'var(--operator-text-muted)',
                fontSize: '13px',
              }}
            >
              Select a connector to view details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
