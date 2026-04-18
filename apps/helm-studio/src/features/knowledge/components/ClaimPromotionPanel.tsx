import { usePromoteClaim } from '../hooks';
import type { KnowledgeClaim } from '../types';

/** Panel for promoting a knowledge claim from LKS to CKS. */
export function ClaimPromotionPanel({
  workspaceId,
  claim,
}: {
  workspaceId: string;
  claim: KnowledgeClaim;
}) {
  const promoteMutation = usePromoteClaim(workspaceId);

  if (claim.storeClass === 'cks') {
    return (
      <div
        style={{
          padding: '10px 12px',
          borderRadius: '8px',
          background: 'rgba(80, 220, 120, 0.06)',
          border: '1px solid rgba(80, 220, 120, 0.15)',
          fontSize: '12px',
          color: 'rgba(80, 220, 120, 0.9)',
          fontWeight: 600,
        }}
      >
        This claim is already in the Canonical Knowledge Store.
      </div>
    );
  }

  return (
    <div
      style={{
        padding: '12px',
        borderRadius: '8px',
        border: '1px solid rgba(158, 178, 198, 0.12)',
        background: 'rgba(158, 178, 198, 0.04)',
        display: 'flex',
        flexDirection: 'column',
        gap: '10px',
      }}
    >
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
          Promote to CKS
        </span>
        <p style={{ fontSize: '12px', color: 'var(--operator-text-soft)', margin: '4px 0 0' }}>
          Promote this LKS claim to the Canonical Knowledge Store. Dual-source verification will be applied.
        </p>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
        <span style={{ color: 'var(--operator-text-soft)' }}>Provenance score</span>
        <span style={{ fontWeight: 700, color: 'var(--operator-text)' }}>
          {(claim.provenanceScore * 100).toFixed(0)}%
        </span>
      </div>

      <button
        className="operator-button primary"
        disabled={
          promoteMutation.isPending ||
          claim.status !== 'approved' ||
          claim.provenanceScore < 0.7
        }
        onClick={() =>
          void promoteMutation.mutate({
            claimId: claim.id,
            request: { claimId: claim.id, targetStoreClass: 'cks' },
          })
        }
        type="button"
      >
        {promoteMutation.isPending ? 'Promoting…' : 'Promote to CKS'}
      </button>

      {claim.status !== 'approved' ? (
        <p style={{ fontSize: '11px', color: 'var(--operator-text-muted)', margin: 0 }}>
          Claim must be approved before promotion.
        </p>
      ) : null}

      {promoteMutation.isError ? (
        <p style={{ fontSize: '11px', color: 'var(--operator-tone-danger)', margin: 0 }}>
          {promoteMutation.error instanceof Error
            ? promoteMutation.error.message
            : 'Promotion failed.'}
        </p>
      ) : null}
    </div>
  );
}
