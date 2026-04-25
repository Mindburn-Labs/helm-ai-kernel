import { useOperatorShell } from '../../../operator/layout';
import {
  EmptyState,
  ErrorState,
  LoadingState,
  SurfaceIntro,
  TopStatusPill,
} from '../../../operator/components';
import { useLksClaims, usePromoteClaim, useRejectClaim } from '../hooks';
import { useKnowledgeStore } from '../store';
import { ProvenanceGraph } from '../components/ProvenanceGraph';
import { ClaimPromotionPanel } from '../components/ClaimPromotionPanel';
import type { ClaimStatus } from '../types';

export function LKSFeedPage() {
  const shell = useOperatorShell();
  const store = useKnowledgeStore();

  const { data, isLoading, isError, error, refetch } = useLksClaims(shell.workspaceId, {
    status: store.filterStatus ?? undefined,
  });

  const promoteMutation = usePromoteClaim(shell.workspaceId);
  const rejectMutation = useRejectClaim(shell.workspaceId);

  const claims = data?.claims ?? [];
  const selectedClaim = claims.find((c) => c.id === store.selectedClaimId) ?? null;

  if (isLoading) {
    return <LoadingState label="Loading LKS feed..." />;
  }

  if (isError) {
    return (
      <ErrorState
        error={error}
        retry={() => void refetch()}
        title="Could not load LKS claims"
      />
    );
  }

  const pendingCount = claims.filter((c) => c.status === 'pending').length;
  const approvedCount = claims.filter((c) => c.status === 'approved').length;

  return (
    <div className="operator-surface-page">
      <SurfaceIntro
        eyebrow="Knowledge / LKS"
        title="Live Knowledge Store"
        description="Review incoming knowledge claims. Approve high-provenance claims and promote to the Canonical Knowledge Store when ready."
        actions={
          <div className="operator-rail-status">
            <TopStatusPill label="Total" tone="neutral" value={String(claims.length)} />
            <TopStatusPill label="Pending" tone="warning" value={String(pendingCount)} />
            <TopStatusPill label="Approved" tone="success" value={String(approvedCount)} />
          </div>
        }
      />

      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '0 0 12px' }}>
        <select
          onChange={(e) => store.setFilterStatus((e.target.value || null) as ClaimStatus | null)}
          style={{ fontSize: '12px' }}
          value={store.filterStatus ?? ''}
        >
          <option value="">All statuses</option>
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="rejected">Rejected</option>
        </select>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '16px',
          minHeight: '400px',
        }}
      >
        {/* Left: claim list */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', overflow: 'auto' }}>
          {claims.length === 0 ? (
            <EmptyState compact title="No LKS claims" body="No claims match the current filter." />
          ) : (
            claims.map((claim) => (
              <div
                key={claim.id}
                style={{
                  padding: '10px 12px',
                  borderRadius: '8px',
                  border:
                    store.selectedClaimId === claim.id
                      ? '1px solid rgba(109, 211, 255, 0.2)'
                      : '1px solid rgba(158, 178, 198, 0.08)',
                  background:
                    store.selectedClaimId === claim.id
                      ? 'rgba(109, 211, 255, 0.08)'
                      : 'transparent',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '3px',
                }}
                onClick={() => store.setSelectedClaim(claim.id)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    store.setSelectedClaim(claim.id);
                  }
                }}
              >
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--operator-text)' }}>
                  {claim.title}
                </span>
                <div style={{ display: 'flex', gap: '8px', fontSize: '11px', color: 'var(--operator-text-muted)' }}>
                  <span
                    style={{
                      padding: '1px 5px',
                      borderRadius: '3px',
                      background: 'rgba(158, 178, 198, 0.08)',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                    }}
                  >
                    {claim.status}
                  </span>
                  <span>Score: {(claim.provenanceScore * 100).toFixed(0)}%</span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Right: detail panel */}
        <div style={{ borderLeft: '1px solid rgba(158, 178, 198, 0.1)', paddingLeft: '16px', overflow: 'auto' }}>
          {selectedClaim ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div>
                <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--operator-text)', margin: 0 }}>
                  {selectedClaim.title}
                </h3>
                <p style={{ fontSize: '12px', color: 'var(--operator-text-soft)', marginTop: '6px' }}>
                  {selectedClaim.body}
                </p>
              </div>

              <ProvenanceGraph claim={selectedClaim} />
              <ClaimPromotionPanel workspaceId={shell.workspaceId} claim={selectedClaim} />

              {selectedClaim.status === 'pending' ? (
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    className="operator-button primary"
                    disabled={promoteMutation.isPending}
                    onClick={() =>
                      void promoteMutation.mutate({
                        claimId: selectedClaim.id,
                        request: { claimId: selectedClaim.id, targetStoreClass: 'cks' },
                      })
                    }
                    type="button"
                  >
                    Promote
                  </button>
                  <button
                    className="operator-button danger"
                    disabled={rejectMutation.isPending}
                    onClick={() =>
                      void rejectMutation.mutate({
                        claimId: selectedClaim.id,
                        reason: 'Rejected by operator',
                      })
                    }
                    type="button"
                  >
                    Reject
                  </button>
                </div>
              ) : null}
            </div>
          ) : (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: 'var(--operator-text-muted)',
                fontSize: '13px',
              }}
            >
              Select a claim to view details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
