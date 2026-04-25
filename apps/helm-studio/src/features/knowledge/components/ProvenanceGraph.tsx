import type { KnowledgeClaim } from '../types';

/** Displays provenance score and source references for a knowledge claim. */
export function ProvenanceGraph({ claim }: { claim: KnowledgeClaim }) {
  const scorePercent = Math.round(claim.provenanceScore * 100);
  const scoreColor =
    scorePercent >= 80
      ? 'rgba(80, 220, 120, 0.9)'
      : scorePercent >= 50
        ? 'var(--operator-tone-warning)'
        : 'var(--operator-tone-danger)';

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '10px',
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
        Provenance
      </span>

      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <div
          style={{
            position: 'relative',
            width: '48px',
            height: '48px',
            flexShrink: 0,
          }}
        >
          <svg width="48" height="48" viewBox="0 0 48 48">
            <circle cx="24" cy="24" r="20" fill="none" stroke="rgba(158,178,198,0.1)" strokeWidth="4" />
            <circle
              cx="24"
              cy="24"
              r="20"
              fill="none"
              stroke={scoreColor}
              strokeWidth="4"
              strokeDasharray={`${(scorePercent / 100) * 125.6} 125.6`}
              strokeLinecap="round"
              transform="rotate(-90 24 24)"
            />
          </svg>
          <span
            style={{
              position: 'absolute',
              inset: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '10px',
              fontWeight: 700,
              color: scoreColor,
            }}
          >
            {scorePercent}%
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
          <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--operator-text)' }}>
            Provenance score
          </span>
          <span style={{ fontSize: '11px', color: 'var(--operator-text-muted)' }}>
            {claim.dualSourceRequired ? 'Dual source required' : 'Single source acceptable'}
          </span>
        </div>
      </div>

      {claim.sourceRefs.length > 0 ? (
        <div>
          <span
            style={{
              fontSize: '10px',
              color: 'var(--operator-text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
            }}
          >
            Source references
          </span>
          <ul
            style={{
              margin: '6px 0 0',
              padding: '0 0 0 14px',
              display: 'flex',
              flexDirection: 'column',
              gap: '2px',
            }}
          >
            {claim.sourceRefs.map((ref) => (
              <li key={ref} style={{ fontSize: '11px', color: 'var(--operator-text-soft)' }}>
                {ref}
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p style={{ fontSize: '11px', color: 'var(--operator-text-muted)', margin: 0 }}>
          No source references attached.
        </p>
      )}
    </div>
  );
}
