import { useActionProposal } from '../hooks';
import { DraftPreview } from './DraftPreview';
import { ContextSlicePanel } from './ContextSlicePanel';
import { ReceiptLineage } from './ReceiptLineage';
import { PolicyVerdictBadge } from './PolicyVerdictBadge';
import { RiskClassPill } from './RiskClassPill';
import type { ProposalDecision } from '../types';

/** Right-side detail panel for the selected proposal in the inbox split view. */
export function ProposalDetailPanel({
  workspaceId,
  proposalId,
  onDecide,
}: {
  workspaceId: string;
  proposalId: string;
  onDecide: (decision: ProposalDecision, reason?: string) => void;
}) {
  const { data: proposal, isLoading } = useActionProposal(workspaceId, proposalId);

  if (isLoading) {
    return (
      <div style={{ padding: '20px', color: 'var(--operator-text-muted)', fontSize: '13px' }}>
        Loading...
      </div>
    );
  }

  if (!proposal) {
    return (
      <div style={{ padding: '20px', color: 'var(--operator-text-muted)', fontSize: '13px' }}>
        Proposal not found.
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '16px' }}>
      {/* Header */}
      <div>
        <h3 style={{ margin: '0 0 8px', fontSize: '15px', color: 'var(--operator-text)' }}>
          {proposal.summary}
        </h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <RiskClassPill riskClass={proposal.risk_class} />
          <PolicyVerdictBadge verdict={proposal.policy_verdict} />
          <span
            style={{
              fontSize: '11px',
              fontWeight: 600,
              padding: '2px 8px',
              borderRadius: '6px',
              background: 'rgba(158, 178, 198, 0.08)',
              color: 'var(--operator-text-muted)',
            }}
          >
            {proposal.status}
          </span>
        </div>
      </div>

      {/* Meta */}
      <dl
        style={{
          margin: 0,
          display: 'grid',
          gridTemplateColumns: 'auto 1fr',
          gap: '4px 12px',
          fontSize: '12px',
        }}
      >
        <dt style={{ fontWeight: 600, color: 'var(--operator-text-soft)' }}>Effect type</dt>
        <dd style={{ margin: 0, color: 'var(--operator-text)' }}>{proposal.effect_type}</dd>

        <dt style={{ fontWeight: 600, color: 'var(--operator-text-soft)' }}>Connector</dt>
        <dd style={{ margin: 0, color: 'var(--operator-text)' }}>{proposal.connector_id}</dd>

        <dt style={{ fontWeight: 600, color: 'var(--operator-text-soft)' }}>Tool</dt>
        <dd style={{ margin: 0, color: 'var(--operator-text)' }}>{proposal.tool_name}</dd>

        <dt style={{ fontWeight: 600, color: 'var(--operator-text-soft)' }}>Priority</dt>
        <dd style={{ margin: 0, color: 'var(--operator-text)' }}>{proposal.priority}</dd>

        <dt style={{ fontWeight: 600, color: 'var(--operator-text-soft)' }}>Created</dt>
        <dd style={{ margin: 0, color: 'var(--operator-text)' }}>
          {new Date(proposal.created_at).toLocaleString()}
        </dd>

        {proposal.expires_at ? (
          <>
            <dt style={{ fontWeight: 600, color: 'var(--operator-text-soft)' }}>Expires</dt>
            <dd style={{ margin: 0, color: 'var(--operator-text)' }}>
              {new Date(proposal.expires_at).toLocaleString()}
            </dd>
          </>
        ) : null}

        {proposal.program_id ? (
          <>
            <dt style={{ fontWeight: 600, color: 'var(--operator-text-soft)' }}>Program</dt>
            <dd style={{ margin: 0, color: 'var(--operator-text)' }}>{proposal.program_id}</dd>
          </>
        ) : null}
      </dl>

      {/* Draft artifact */}
      {proposal.draft_artifact ? (
        <div>
          <h4 style={{ margin: '0 0 6px', fontSize: '13px', color: 'var(--operator-text-soft)' }}>
            Draft Preview
          </h4>
          <DraftPreview artifact={proposal.draft_artifact} />
        </div>
      ) : null}

      {/* Context slice */}
      {proposal.context_slice ? (
        <div>
          <h4 style={{ margin: '0 0 6px', fontSize: '13px', color: 'var(--operator-text-soft)' }}>
            Context
          </h4>
          <ContextSlicePanel slice={proposal.context_slice} />
        </div>
      ) : null}

      {/* Receipt lineage */}
      {proposal.receipt_lineage && proposal.receipt_lineage.length > 0 ? (
        <div>
          <h4 style={{ margin: '0 0 6px', fontSize: '13px', color: 'var(--operator-text-soft)' }}>
            Receipt Lineage
          </h4>
          <ReceiptLineage hashes={proposal.receipt_lineage} />
        </div>
      ) : null}

      {/* Decision buttons */}
      {proposal.status === 'PROPOSED' ? (
        <div style={{ display: 'flex', gap: '8px', paddingTop: '8px' }}>
          <button
            onClick={() => onDecide('APPROVE')}
            style={{
              padding: '6px 14px',
              borderRadius: '6px',
              border: '1px solid rgba(121, 216, 166, 0.3)',
              background: 'rgba(121, 216, 166, 0.12)',
              color: 'var(--operator-success)',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
            }}
            type="button"
          >
            Approve
          </button>
          <button
            onClick={() => onDecide('DENY')}
            style={{
              padding: '6px 14px',
              borderRadius: '6px',
              border: '1px solid rgba(255, 122, 112, 0.3)',
              background: 'rgba(255, 122, 112, 0.12)',
              color: 'var(--operator-danger)',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
            }}
            type="button"
          >
            Deny
          </button>
          <button
            onClick={() => onDecide('DEFER')}
            style={{
              padding: '6px 14px',
              borderRadius: '6px',
              border: '1px solid rgba(255, 185, 104, 0.3)',
              background: 'rgba(255, 185, 104, 0.12)',
              color: 'var(--operator-warning)',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
            }}
            type="button"
          >
            Defer
          </button>
        </div>
      ) : null}
    </div>
  );
}
