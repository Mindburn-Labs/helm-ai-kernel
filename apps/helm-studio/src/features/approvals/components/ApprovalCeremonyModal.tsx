import { useState } from 'react';
import { useResolveCeremony } from '../hooks';
import { QuorumPanel } from './QuorumPanel';
import { TimelockCountdown } from './TimelockCountdown';
import type { ApprovalCeremony } from '../types';

/** Modal for completing an approval ceremony — shows intent hash, quorum requirements, and reason code selection. */
export function ApprovalCeremonyModal({
  workspaceId,
  ceremony,
  onClose,
}: {
  workspaceId: string;
  ceremony: ApprovalCeremony;
  onClose: () => void;
}) {
  const [selectedReason, setSelectedReason] = useState(
    ceremony.reasonCodeOptions[0] ?? '',
  );
  const resolveMutation = useResolveCeremony(workspaceId);

  const handleComplete = () => {
    void resolveMutation.mutate(
      {
        ceremonyId: ceremony.id,
        request: {
          challengeHash: ceremony.challengeHash,
          responseHash: ceremony.responseHash,
          reasonCode: selectedReason,
        },
      },
      { onSuccess: onClose },
    );
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(0, 0, 0, 0.6)',
        zIndex: 1000,
      }}
    >
      <div
        style={{
          width: '480px',
          maxWidth: '90vw',
          borderRadius: '12px',
          border: '1px solid rgba(158, 178, 198, 0.15)',
          background: 'var(--operator-surface)',
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div>
            <span
              style={{
                fontSize: '10px',
                fontWeight: 700,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                color: 'var(--operator-text-muted)',
              }}
            >
              Approval Ceremony
            </span>
            <h2 style={{ fontSize: '16px', fontWeight: 700, margin: '4px 0 0', color: 'var(--operator-text)' }}>
              {ceremony.requiredAction}
            </h2>
          </div>
          <TimelockCountdown timelockMs={ceremony.timelockMs} startedAtMs={Date.now()} />
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <span style={{ fontSize: '10px', color: 'var(--operator-text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Intent hash
          </span>
          <code style={{ fontSize: '11px', color: 'var(--operator-text-soft)', wordBreak: 'break-all' }}>
            {ceremony.intentHash}
          </code>
        </div>

        <QuorumPanel ceremony={ceremony} />

        {ceremony.reasonCodeOptions.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label
              htmlFor="reason-code-select"
              style={{ fontSize: '12px', color: 'var(--operator-text-soft)' }}
            >
              Select reason code
            </label>
            <select
              id="reason-code-select"
              value={selectedReason}
              onChange={(e) => setSelectedReason(e.target.value)}
              style={{ fontSize: '12px' }}
            >
              {ceremony.reasonCodeOptions.map((code) => (
                <option key={code} value={code}>
                  {code}
                </option>
              ))}
            </select>
          </div>
        ) : null}

        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', paddingTop: '8px' }}>
          <button
            className="operator-button ghost"
            onClick={onClose}
            type="button"
          >
            Cancel
          </button>
          <button
            className="operator-button primary"
            disabled={resolveMutation.isPending || ceremony.status === 'expired'}
            onClick={handleComplete}
            type="button"
          >
            {resolveMutation.isPending ? 'Completing…' : 'Complete ceremony'}
          </button>
        </div>

        {resolveMutation.isError ? (
          <p style={{ fontSize: '12px', color: 'var(--operator-tone-danger)', margin: 0 }}>
            {resolveMutation.error instanceof Error
              ? resolveMutation.error.message
              : 'Failed to complete ceremony.'}
          </p>
        ) : null}
      </div>
    </div>
  );
}
