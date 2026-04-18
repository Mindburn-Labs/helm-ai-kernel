import { useState } from 'react';

/**
 * Panel for placing a legal hold on one or more runs.
 *
 * NOTE: The evidence feature does not have a backend endpoint for legal holds.
 * Use the trust-portal legal-hold feature instead. This component is retained
 * as a placeholder for future integration.
 */
export function LegalHoldPanel({ workspaceId: _workspaceId }: { workspaceId: string }) {
  const [runIdsInput, setRunIdsInput] = useState('');
  const [holdReason, setHoldReason] = useState('');
  const [confirmed, setConfirmed] = useState(false);

  return (
    <div
      style={{
        padding: '12px',
        borderRadius: '8px',
        border: '1px solid rgba(255, 200, 50, 0.15)',
        background: 'rgba(255, 200, 50, 0.04)',
        display: 'flex',
        flexDirection: 'column',
        gap: '10px',
      }}
    >
      <span
        style={{
          fontSize: '10px',
          fontWeight: 700,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          color: 'var(--operator-tone-warning)',
        }}
      >
        Legal Hold
      </span>

      <p style={{ fontSize: '12px', color: 'var(--operator-text-soft)', margin: 0 }}>
        Placing a legal hold prevents deletion or modification of the specified run evidence packs.
        Use the Trust Portal to manage legal holds.
      </p>

      <textarea
        placeholder="Run IDs (comma or newline separated)..."
        rows={2}
        style={{
          resize: 'vertical',
          fontSize: '12px',
          padding: '8px',
          borderRadius: '6px',
          border: '1px solid rgba(158, 178, 198, 0.2)',
          background: 'rgba(0, 0, 0, 0.2)',
          color: 'var(--operator-text)',
          fontFamily: 'monospace',
        }}
        value={runIdsInput}
        onChange={(e) => setRunIdsInput(e.target.value)}
      />

      <input
        placeholder="Hold reason (required)"
        style={{
          fontSize: '12px',
          padding: '8px',
          borderRadius: '6px',
          border: '1px solid rgba(158, 178, 198, 0.2)',
          background: 'rgba(0, 0, 0, 0.2)',
          color: 'var(--operator-text)',
        }}
        type="text"
        value={holdReason}
        onChange={(e) => setHoldReason(e.target.value)}
      />

      <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', cursor: 'pointer' }}>
        <input
          checked={confirmed}
          onChange={(e) => setConfirmed(e.target.checked)}
          type="checkbox"
        />
        <span style={{ color: 'var(--operator-text-soft)' }}>
          I confirm this hold is legally required and authorized.
        </span>
      </label>

      <button
        className="operator-button secondary"
        disabled={!runIdsInput.trim() || !holdReason.trim() || !confirmed}
        type="button"
      >
        Place legal hold (via Trust Portal)
      </button>
    </div>
  );
}
