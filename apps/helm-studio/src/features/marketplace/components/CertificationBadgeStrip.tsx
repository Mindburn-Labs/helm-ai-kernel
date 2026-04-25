import type { MarketplaceConnector } from '../types';

/** Horizontal strip of certification badges and the connector's certification reference. */
export function CertificationBadgeStrip({
  connector,
}: {
  connector: MarketplaceConnector;
}) {
  return (
    <div
      style={{
        padding: '10px 12px',
        borderRadius: '8px',
        border: '1px solid rgba(158, 178, 198, 0.1)',
        background: 'rgba(158, 178, 198, 0.03)',
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
      }}
    >
      <span
        style={{
          fontSize: '10px',
          fontWeight: 700,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          color: 'var(--operator-text-muted)',
        }}
      >
        Certification
      </span>

      {connector.certificationRef ? (
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
          <span style={{ color: 'var(--operator-text-soft)' }}>Certification ref</span>
          <code style={{ fontSize: '11px', color: 'var(--operator-text)' }}>
            {connector.certificationRef}
          </code>
        </div>
      ) : (
        <span style={{ fontSize: '12px', color: 'var(--operator-text-muted)', fontStyle: 'italic' }}>
          No certification on file.
        </span>
      )}

      {connector.lastVerifiedAt ? (
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
          <span style={{ color: 'var(--operator-text-soft)' }}>Last verified</span>
          <span style={{ color: 'var(--operator-text)' }}>
            {new Date(connector.lastVerifiedAt).toLocaleDateString()}
          </span>
        </div>
      ) : null}

      {connector.badges.length > 0 ? (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', paddingTop: '2px' }}>
          {connector.badges.map((badge) => (
            <span
              key={badge}
              style={{
                fontSize: '10px',
                padding: '3px 8px',
                borderRadius: '4px',
                border: '1px solid rgba(80, 220, 120, 0.2)',
                color: 'rgba(80, 220, 120, 0.8)',
                fontWeight: 600,
              }}
            >
              {badge}
            </span>
          ))}
        </div>
      ) : null}
    </div>
  );
}
