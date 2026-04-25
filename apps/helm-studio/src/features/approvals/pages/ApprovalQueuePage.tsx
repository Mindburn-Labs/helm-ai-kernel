import { useState } from 'react';
import { useOperatorShell } from '../../../operator/layout';
import {
  EmptyState,
  ErrorState,
  LoadingState,
  SurfaceIntro,
  TopStatusPill,
} from '../../../operator/components';
import { useApprovals } from '../hooks';
import { useApprovalsStore } from '../store';
import { ApprovalCeremonyModal } from '../components/ApprovalCeremonyModal';
import { TimelockCountdown } from '../components/TimelockCountdown';
import type { ApprovalCeremony } from '../types';

export function ApprovalQueuePage() {
  const shell = useOperatorShell();
  const store = useApprovalsStore();
  const [modalCeremony, setModalCeremony] = useState<ApprovalCeremony | null>(null);

  const { data, isLoading, isError, error, refetch } = useApprovals(shell.workspaceId, {
    status: store.filterStatus ?? undefined,
  });

  const ceremonies = data?.ceremonies ?? [];

  if (isLoading) {
    return <LoadingState label="Loading approval queue..." />;
  }

  if (isError) {
    return (
      <ErrorState
        error={error}
        retry={() => void refetch()}
        title="Could not load approval ceremonies"
      />
    );
  }

  const pendingCount = ceremonies.filter((c) => c.status === 'pending').length;
  const inProgressCount = ceremonies.filter((c) => c.status === 'in_progress').length;
  const expiredCount = ceremonies.filter((c) => c.status === 'expired').length;

  return (
    <div className="operator-surface-page">
      <SurfaceIntro
        eyebrow="Approvals / Queue"
        title="Approval Queue"
        description="Review cryptographic approval ceremonies. Each ceremony is time-locked and requires a signed response from an authorized principal."
        actions={
          <div className="operator-rail-status">
            <TopStatusPill label="Pending" tone="warning" value={String(pendingCount)} />
            <TopStatusPill label="In Progress" tone="info" value={String(inProgressCount)} />
            <TopStatusPill label="Expired" tone="danger" value={String(expiredCount)} />
          </div>
        }
      />

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          padding: '0 0 12px',
        }}
      >
        <select
          onChange={(e) =>
            store.setFilterStatus(
              (e.target.value || null) as 'pending' | 'in_progress' | 'completed' | 'expired' | null,
            )
          }
          style={{ fontSize: '12px' }}
          value={store.filterStatus ?? ''}
        >
          <option value="">All statuses</option>
          <option value="pending">Pending</option>
          <option value="in_progress">In Progress</option>
          <option value="completed">Completed</option>
          <option value="expired">Expired</option>
        </select>
      </div>

      {ceremonies.length === 0 ? (
        <EmptyState
          title="No approval ceremonies"
          body="No ceremonies match the current filter. Ceremonies are created when an intent requires human cryptographic approval."
        />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {ceremonies.map((ceremony) => (
            <div
              key={ceremony.id}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '12px 14px',
                borderRadius: '8px',
                border: '1px solid rgba(158, 178, 198, 0.1)',
                background:
                  store.selectedCeremonyId === ceremony.id
                    ? 'rgba(109, 211, 255, 0.06)'
                    : 'transparent',
                cursor: 'pointer',
              }}
              onClick={() => store.setSelectedCeremony(ceremony.id)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  store.setSelectedCeremony(ceremony.id);
                }
              }}
            >
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '3px' }}>
                <span
                  style={{
                    fontSize: '13px',
                    fontWeight: 600,
                    color: 'var(--operator-text)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {ceremony.requiredAction}
                </span>
                <span style={{ fontSize: '11px', color: 'var(--operator-text-muted)' }}>
                  {ceremony.signerPrincipal}
                </span>
              </div>

              <span
                style={{
                  fontSize: '10px',
                  padding: '2px 6px',
                  borderRadius: '4px',
                  background: 'rgba(158, 178, 198, 0.08)',
                  color: 'var(--operator-text-muted)',
                  textTransform: 'uppercase',
                  fontWeight: 700,
                  letterSpacing: '0.06em',
                }}
              >
                {ceremony.status.replace('_', ' ')}
              </span>

              {ceremony.status === 'pending' || ceremony.status === 'in_progress' ? (
                <TimelockCountdown
                  timelockMs={ceremony.timelockMs}
                  startedAtMs={ceremony.completedAtMs ?? Date.now()}
                />
              ) : null}

              {ceremony.status === 'pending' ? (
                <button
                  className="operator-button primary"
                  onClick={(e) => {
                    e.stopPropagation();
                    setModalCeremony(ceremony);
                  }}
                  style={{ fontSize: '11px', padding: '4px 10px' }}
                  type="button"
                >
                  Review
                </button>
              ) : null}
            </div>
          ))}
        </div>
      )}

      {modalCeremony ? (
        <ApprovalCeremonyModal
          workspaceId={shell.workspaceId}
          ceremony={modalCeremony}
          onClose={() => setModalCeremony(null)}
        />
      ) : null}
    </div>
  );
}
