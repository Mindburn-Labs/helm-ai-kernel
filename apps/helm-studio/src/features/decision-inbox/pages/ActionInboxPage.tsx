import { useOperatorShell } from '../../../operator/layout';
import { EmptyState, ErrorState, LoadingState, SurfaceIntro, TopStatusPill } from '../../../operator/components';
import { useActionProposals, useDecideAction, useBatchDecide } from '../hooks';
import { useActionInboxStore } from '../store';
import { ProposalRow } from '../components/ProposalRow';
import { ProposalDetailPanel } from '../components/ProposalDetailPanel';
import { BatchToolbar } from '../components/BatchToolbar';
import type { ActionProposalRecord, RiskClass } from '../types';

export function ActionInboxPage() {
  const shell = useOperatorShell();
  const store = useActionInboxStore();

  const { data, isLoading, isError, error, refetch } = useActionProposals(shell.workspaceId, {
    status: store.filterStatus ?? undefined,
    risk_class: store.filterRiskClass ?? undefined,
    program_id: store.filterProgramId ?? undefined,
  });
  const decideMutation = useDecideAction(shell.workspaceId);
  const batchMutation = useBatchDecide(shell.workspaceId);

  const proposals = data?.proposals ?? [];
  const hasBatchSelection = store.selectedForBatch.size > 0;

  if (isLoading) {
    return <LoadingState label="Loading action proposals..." />;
  }

  if (isError) {
    return (
      <ErrorState
        error={error}
        retry={() => void refetch()}
        title="Could not load action proposals"
      />
    );
  }

  const proposedCount = proposals.filter((p) => p.status === 'PROPOSED').length;
  const escalatedCount = proposals.filter((p) => p.policy_verdict === 'ESCALATE').length;

  return (
    <div className="operator-surface-page">
      <SurfaceIntro
        eyebrow="Actions / Inbox"
        title="Action Inbox"
        description="Review and decide on AI-proposed actions. Each proposal includes a policy verdict, risk class, and optional draft artifact for human review."
        actions={
          <div className="operator-rail-status">
            <TopStatusPill label="Total" tone="neutral" value={String(proposals.length)} />
            <TopStatusPill label="Proposed" tone="info" value={String(proposedCount)} />
            <TopStatusPill label="Escalated" tone="warning" value={String(escalatedCount)} />
          </div>
        }
      />

      {hasBatchSelection ? (
        <BatchToolbar
          selectedCount={store.selectedForBatch.size}
          onApprove={() =>
            void batchMutation.mutate({
              proposalIds: [...store.selectedForBatch],
              decision: 'APPROVE',
            })
          }
          onDeny={() =>
            void batchMutation.mutate({
              proposalIds: [...store.selectedForBatch],
              decision: 'DENY',
            })
          }
          onDefer={() =>
            void batchMutation.mutate({
              proposalIds: [...store.selectedForBatch],
              decision: 'DEFER',
            })
          }
          onClear={() => store.clearBatchSelection()}
        />
      ) : null}

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          padding: '0 0 12px',
        }}
      >
        <select
          onChange={(e) => store.setFilterStatus(e.target.value || null)}
          style={{ fontSize: '12px' }}
          value={store.filterStatus ?? ''}
        >
          <option value="">All statuses</option>
          <option value="PROPOSED">Proposed</option>
          <option value="APPROVED">Approved</option>
          <option value="IN_PROGRESS">In Progress</option>
          <option value="COMPLETED">Completed</option>
          <option value="REJECTED">Rejected</option>
          <option value="DEFERRED">Deferred</option>
        </select>

        <select
          onChange={(e) => store.setFilterRiskClass((e.target.value || null) as RiskClass | null)}
          style={{ fontSize: '12px' }}
          value={store.filterRiskClass ?? ''}
        >
          <option value="">All risk classes</option>
          <option value="R0">R0 - Read-only</option>
          <option value="R1">R1 - Internal</option>
          <option value="R2">R2 - External</option>
          <option value="R3">R3 - Critical</option>
        </select>

        <select
          onChange={(e) => store.setSortBy(e.target.value as 'priority' | 'created_at' | 'risk_class')}
          style={{ fontSize: '12px' }}
          value={store.sortBy}
        >
          <option value="priority">Priority</option>
          <option value="created_at">Newest</option>
          <option value="risk_class">Risk class</option>
        </select>

        {proposals.length > 0 ? (
          <button
            onClick={() => store.selectAllForBatch(proposals.map((p) => p.id))}
            style={{
              marginLeft: 'auto',
              padding: '4px 10px',
              borderRadius: '6px',
              border: '1px solid rgba(158, 178, 198, 0.2)',
              background: 'transparent',
              color: 'var(--operator-text-muted)',
              fontSize: '11px',
              fontWeight: 600,
              cursor: 'pointer',
            }}
            type="button"
          >
            Select all
          </button>
        ) : null}
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '16px',
          minHeight: '400px',
        }}
      >
        {/* Left: proposal list */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', overflow: 'auto' }}>
          {proposals.length === 0 ? (
            <EmptyState
              compact
              title="No proposals"
              body="No proposals match the current filters."
            />
          ) : (
            proposals.map((proposal: ActionProposalRecord) => (
              <ProposalRow
                key={proposal.id}
                proposal={proposal}
                isSelected={store.selectedProposalId === proposal.id}
                isBatchSelected={store.selectedForBatch.has(proposal.id)}
                onSelect={() => store.setSelectedProposal(proposal.id)}
                onBatchToggle={() => store.toggleBatchSelect(proposal.id)}
              />
            ))
          )}
        </div>

        {/* Right: detail panel */}
        <div
          style={{
            borderLeft: '1px solid rgba(158, 178, 198, 0.1)',
            overflow: 'auto',
          }}
        >
          {store.selectedProposalId ? (
            <ProposalDetailPanel
              workspaceId={shell.workspaceId}
              proposalId={store.selectedProposalId}
              onDecide={(decision, reason) =>
                void decideMutation.mutate({
                  proposalId: store.selectedProposalId!,
                  decision,
                  reason,
                })
              }
            />
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
              Select a proposal to view details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
