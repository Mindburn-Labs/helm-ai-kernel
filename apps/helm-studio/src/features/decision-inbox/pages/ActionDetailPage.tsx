import { useParams, useNavigate } from 'react-router-dom';
import { useOperatorShell } from '../../../operator/layout';
import { ErrorState, LoadingState } from '../../../operator/components';
import { formatRelativeTime } from '../../../operator/model';
import { useActionProposal, useDecideAction } from '../hooks';
import { DraftPreview } from '../components/DraftPreview';
import { ContextSlicePanel } from '../components/ContextSlicePanel';
import { ReceiptLineage } from '../components/ReceiptLineage';
import { PolicyVerdictBadge } from '../components/PolicyVerdictBadge';
import { RiskClassPill } from '../components/RiskClassPill';

export function ActionDetailPage() {
  const shell = useOperatorShell();
  const navigate = useNavigate();
  const { proposalId } = useParams<{ proposalId: string }>();
  const { data: proposal, isLoading, isError, error, refetch } = useActionProposal(
    shell.workspaceId,
    proposalId!,
  );
  const decideMutation = useDecideAction(shell.workspaceId);

  if (isLoading) {
    return <LoadingState label="Loading proposal..." />;
  }

  if (isError) {
    return (
      <ErrorState error={error} retry={() => void refetch()} title="Could not load proposal" />
    );
  }

  if (!proposal) {
    return (
      <div
        style={{
          padding: '40px',
          textAlign: 'center',
          color: 'var(--operator-text-muted)',
          fontSize: '14px',
        }}
      >
        Proposal not found.
      </div>
    );
  }

  return (
    <div className="operator-surface-page">
      {/* Back link */}
      <button
        onClick={() => void navigate(`/workspaces/${shell.workspaceId}/actions`)}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '4px',
          padding: '4px 0',
          border: 'none',
          background: 'transparent',
          color: 'var(--operator-accent)',
          fontSize: '12px',
          fontWeight: 600,
          cursor: 'pointer',
          marginBottom: '12px',
        }}
        type="button"
      >
        &larr; Back to inbox
      </button>

      {/* Header */}
      <header style={{ marginBottom: '20px' }}>
        <h2 style={{ margin: '0 0 10px', fontSize: '18px', color: 'var(--operator-text)' }}>
          {proposal.summary}
        </h2>
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
      </header>

      {/* Meta section */}
      <section
        style={{
          padding: '14px',
          borderRadius: '10px',
          background: 'rgba(158, 178, 198, 0.04)',
          border: '1px solid rgba(158, 178, 198, 0.1)',
          marginBottom: '16px',
        }}
      >
        <dl
          style={{
            margin: 0,
            display: 'grid',
            gridTemplateColumns: 'auto 1fr',
            gap: '6px 16px',
            fontSize: '13px',
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
            {formatRelativeTime(proposal.created_at)}
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

          {proposal.employee_id ? (
            <>
              <dt style={{ fontWeight: 600, color: 'var(--operator-text-soft)' }}>Employee</dt>
              <dd style={{ margin: 0, color: 'var(--operator-text)' }}>{proposal.employee_id}</dd>
            </>
          ) : null}

          {proposal.source_signal_id ? (
            <>
              <dt style={{ fontWeight: 600, color: 'var(--operator-text-soft)' }}>Source signal</dt>
              <dd style={{ margin: 0 }}>
                <code
                  style={{
                    fontSize: '11px',
                    color: 'var(--operator-text-muted)',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  {proposal.source_signal_id}
                </code>
              </dd>
            </>
          ) : null}
        </dl>
      </section>

      {/* Draft artifact */}
      {proposal.draft_artifact ? (
        <section style={{ marginBottom: '16px' }}>
          <h3 style={{ margin: '0 0 8px', fontSize: '14px', color: 'var(--operator-text)' }}>
            Draft Preview
          </h3>
          <DraftPreview artifact={proposal.draft_artifact} />
        </section>
      ) : null}

      {/* Context slice */}
      {proposal.context_slice ? (
        <section style={{ marginBottom: '16px' }}>
          <h3 style={{ margin: '0 0 8px', fontSize: '14px', color: 'var(--operator-text)' }}>
            Context
          </h3>
          <ContextSlicePanel slice={proposal.context_slice} />
        </section>
      ) : null}

      {/* Receipt lineage */}
      {proposal.receipt_lineage && proposal.receipt_lineage.length > 0 ? (
        <section style={{ marginBottom: '16px' }}>
          <h3 style={{ margin: '0 0 8px', fontSize: '14px', color: 'var(--operator-text)' }}>
            Receipt Lineage
          </h3>
          <ReceiptLineage hashes={proposal.receipt_lineage} />
        </section>
      ) : null}

      {/* Decision buttons */}
      {proposal.status === 'PROPOSED' ? (
        <footer
          style={{
            display: 'flex',
            gap: '10px',
            paddingTop: '16px',
            borderTop: '1px solid rgba(158, 178, 198, 0.1)',
          }}
        >
          <button
            onClick={() =>
              void decideMutation.mutate({ proposalId: proposal.id, decision: 'APPROVE' })
            }
            style={{
              padding: '8px 18px',
              borderRadius: '8px',
              border: '1px solid rgba(121, 216, 166, 0.3)',
              background: 'rgba(121, 216, 166, 0.12)',
              color: 'var(--operator-success)',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
            }}
            type="button"
          >
            Approve
          </button>
          <button
            onClick={() =>
              void decideMutation.mutate({ proposalId: proposal.id, decision: 'DENY' })
            }
            style={{
              padding: '8px 18px',
              borderRadius: '8px',
              border: '1px solid rgba(255, 122, 112, 0.3)',
              background: 'rgba(255, 122, 112, 0.12)',
              color: 'var(--operator-danger)',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
            }}
            type="button"
          >
            Deny
          </button>
          <button
            onClick={() =>
              void decideMutation.mutate({ proposalId: proposal.id, decision: 'DEFER' })
            }
            style={{
              padding: '8px 18px',
              borderRadius: '8px',
              border: '1px solid rgba(255, 185, 104, 0.3)',
              background: 'rgba(255, 185, 104, 0.12)',
              color: 'var(--operator-warning)',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
            }}
            type="button"
          >
            Defer
          </button>
        </footer>
      ) : null}
    </div>
  );
}
