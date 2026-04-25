import type { DraftArtifactRecord } from '../types';

/** Renders a draft artifact's body markdown with its type label and content hash. */
export function DraftPreview({ artifact }: { artifact: DraftArtifactRecord }) {
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
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span
          style={{
            fontSize: '11px',
            fontWeight: 600,
            padding: '2px 6px',
            borderRadius: '4px',
            background: 'rgba(109, 211, 255, 0.12)',
            color: 'var(--operator-accent)',
          }}
        >
          {artifact.artifact_type}
        </span>
        <code
          style={{
            fontSize: '11px',
            color: 'var(--operator-text-muted)',
            fontFamily: 'var(--font-mono)',
          }}
        >
          {artifact.content_hash.slice(0, 12)}...
        </code>
      </div>

      {artifact.body_markdown ? (
        <pre
          style={{
            margin: 0,
            padding: '10px',
            borderRadius: '6px',
            background: 'rgba(0, 0, 0, 0.15)',
            fontSize: '12px',
            lineHeight: 1.5,
            color: 'var(--operator-text)',
            fontFamily: 'var(--font-mono)',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            overflow: 'auto',
            maxHeight: '300px',
          }}
        >
          {artifact.body_markdown}
        </pre>
      ) : (
        <p style={{ color: 'var(--operator-text-muted)', fontSize: '13px', margin: 0 }}>
          No body content available.
        </p>
      )}
    </div>
  );
}
