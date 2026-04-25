import type { ApprovalCeremony } from '../types';

/** Shows signer principal and required action for a ceremony. */
export function QuorumPanel({ ceremony }: { ceremony: ApprovalCeremony }) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        padding: '12px',
        borderRadius: '8px',
        border: '1px solid rgba(158, 178, 198, 0.12)',
        background: 'rgba(158, 178, 198, 0.04)',
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
        Quorum Requirements
      </span>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
          <span style={{ color: 'var(--operator-text-soft)' }}>Signer principal</span>
          <span style={{ color: 'var(--operator-text)', fontWeight: 600 }}>
            {ceremony.signerPrincipal}
          </span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
          <span style={{ color: 'var(--operator-text-soft)' }}>Required action</span>
          <span style={{ color: 'var(--operator-text)', fontWeight: 600 }}>
            {ceremony.requiredAction}
          </span>
        </div>
      </div>

      {ceremony.reasonCodeOptions.length > 0 ? (
        <div>
          <span
            style={{
              fontSize: '10px',
              color: 'var(--operator-text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
            }}
          >
            Reason codes
          </span>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '6px' }}>
            {ceremony.reasonCodeOptions.map((code) => (
              <span
                key={code}
                style={{
                  fontSize: '10px',
                  padding: '2px 6px',
                  borderRadius: '4px',
                  border: '1px solid rgba(158, 178, 198, 0.15)',
                  color: 'var(--operator-text-soft)',
                  background: 'transparent',
                }}
              >
                {code}
              </span>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
