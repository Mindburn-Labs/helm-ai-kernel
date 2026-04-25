import type { MarketplaceConnector } from '../types';

/** Renders a grid of marketplace connectors with their state and badges. */
export function ConnectorCatalog({
  connectors,
  selectedId,
  onSelect,
}: {
  connectors: MarketplaceConnector[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  if (connectors.length === 0) {
    return null;
  }

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))',
        gap: '10px',
      }}
    >
      {connectors.map((connector) => (
        <div
          key={connector.id}
          style={{
            padding: '14px',
            borderRadius: '10px',
            border:
              selectedId === connector.id
                ? '1px solid rgba(109, 211, 255, 0.25)'
                : '1px solid rgba(158, 178, 198, 0.1)',
            background:
              selectedId === connector.id
                ? 'rgba(109, 211, 255, 0.06)'
                : 'rgba(158, 178, 198, 0.02)',
            cursor: 'pointer',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
            transition: 'border-color 0.1s',
          }}
          onClick={() => onSelect(connector.id)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              onSelect(connector.id);
            }
          }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--operator-text)' }}>
              {connector.name}
            </span>
            <span
              style={{
                fontSize: '9px',
                padding: '2px 6px',
                borderRadius: '4px',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.07em',
                background:
                  connector.state === 'certified'
                    ? 'rgba(80, 220, 120, 0.1)'
                    : connector.state === 'revoked'
                      ? 'rgba(255, 100, 100, 0.1)'
                      : 'rgba(158, 178, 198, 0.08)',
                color:
                  connector.state === 'certified'
                    ? 'rgba(80, 220, 120, 0.9)'
                    : connector.state === 'revoked'
                      ? 'var(--operator-tone-danger)'
                      : 'var(--operator-text-muted)',
              }}
            >
              {connector.state}
            </span>
          </div>

          <span style={{ fontSize: '11px', color: 'var(--operator-text-muted)' }}>
            v{connector.version}
          </span>

          {connector.badges.length > 0 ? (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
              {connector.badges.map((badge) => (
                <span
                  key={badge}
                  style={{
                    fontSize: '10px',
                    padding: '1px 5px',
                    borderRadius: '3px',
                    border: '1px solid rgba(109, 211, 255, 0.15)',
                    color: 'rgba(109, 211, 255, 0.7)',
                  }}
                >
                  {badge}
                </span>
              ))}
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}
