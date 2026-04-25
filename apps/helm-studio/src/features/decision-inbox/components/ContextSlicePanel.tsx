import type { ContextSliceRecord } from '../types';

/** Displays context slice metadata: signal IDs, model run, and confidence. */
export function ContextSlicePanel({ slice }: { slice: ContextSliceRecord }) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        padding: '12px 14px',
        borderRadius: '10px',
        background: 'rgba(158, 178, 198, 0.06)',
        border: '1px solid rgba(158, 178, 198, 0.12)',
      }}
    >
      <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 12px' }}>
        <dt style={{ fontSize: '12px', fontWeight: 600, color: 'var(--operator-text-soft)' }}>
          Reasoning hash
        </dt>
        <dd style={{ margin: 0 }}>
          <code
            style={{
              fontSize: '11px',
              color: 'var(--operator-text-muted)',
              fontFamily: 'var(--font-mono)',
            }}
          >
            {slice.reasoning_hash.slice(0, 16)}...
          </code>
        </dd>

        {slice.model_run_id ? (
          <>
            <dt style={{ fontSize: '12px', fontWeight: 600, color: 'var(--operator-text-soft)' }}>
              Model run
            </dt>
            <dd style={{ margin: 0 }}>
              <code
                style={{
                  fontSize: '11px',
                  color: 'var(--operator-text-muted)',
                  fontFamily: 'var(--font-mono)',
                }}
              >
                {slice.model_run_id}
              </code>
            </dd>
          </>
        ) : null}

        {slice.confidence != null ? (
          <>
            <dt style={{ fontSize: '12px', fontWeight: 600, color: 'var(--operator-text-soft)' }}>
              Confidence
            </dt>
            <dd style={{ margin: 0, fontSize: '12px', color: 'var(--operator-text)' }}>
              {(slice.confidence * 100).toFixed(1)}%
            </dd>
          </>
        ) : null}
      </dl>

      {slice.signal_ids.length > 0 ? (
        <div>
          <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--operator-text-soft)' }}>
            Signals ({slice.signal_ids.length})
          </span>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '4px' }}>
            {slice.signal_ids.map((signalId) => (
              <code
                key={signalId}
                style={{
                  fontSize: '10px',
                  padding: '2px 6px',
                  borderRadius: '4px',
                  background: 'rgba(109, 211, 255, 0.08)',
                  color: 'var(--operator-text-muted)',
                  fontFamily: 'var(--font-mono)',
                }}
              >
                {signalId.slice(0, 12)}...
              </code>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
