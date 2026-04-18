import { useState } from 'react';

/** Visual chain of receipt hashes, monospace-truncated with copy on click. */
export function ReceiptLineage({ hashes }: { hashes: string[] }) {
  const [copied, setCopied] = useState<string | null>(null);

  const handleCopy = (hash: string) => {
    void navigator.clipboard.writeText(hash).then(() => {
      setCopied(hash);
      setTimeout(() => setCopied(null), 1500);
    });
  };

  if (hashes.length === 0) {
    return (
      <p style={{ color: 'var(--operator-text-muted)', fontSize: '13px', margin: 0 }}>
        No receipt lineage.
      </p>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
      {hashes.map((hash, index) => (
        <div
          key={hash}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <span
            style={{
              fontSize: '10px',
              fontWeight: 600,
              color: 'var(--operator-text-soft)',
              width: '18px',
              textAlign: 'right',
              flexShrink: 0,
            }}
          >
            {index + 1}
          </span>
          <div
            style={{
              width: '12px',
              height: '1px',
              background: 'rgba(158, 178, 198, 0.2)',
              flexShrink: 0,
            }}
          />
          <button
            onClick={() => handleCopy(hash)}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '3px 8px',
              borderRadius: '4px',
              border: '1px solid rgba(158, 178, 198, 0.12)',
              background: 'rgba(0, 0, 0, 0.1)',
              cursor: 'pointer',
              color: 'var(--operator-text-muted)',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
            }}
            title="Click to copy full hash"
            type="button"
          >
            {hash.slice(0, 16)}...{hash.slice(-8)}
            {copied === hash ? (
              <span style={{ fontSize: '10px', color: 'var(--operator-success)' }}>copied</span>
            ) : null}
          </button>
        </div>
      ))}
    </div>
  );
}
