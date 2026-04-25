import { useOperatorShell } from '../../../operator/layout';
import {
  EmptyState,
  ErrorState,
  LoadingState,
  SurfaceIntro,
  TopStatusPill,
} from '../../../operator/components';
import { useSkillCandidates, usePromoteCandidate, useRejectCandidate } from '../hooks';
import { useSkillsStore } from '../store';
import { CanaryRolloutPanel } from '../components/CanaryRolloutPanel';
import { SkillManifestPanel } from '../components/SkillManifestPanel';
import type { QueueStatus, SelfModClass } from '../types';

export function CandidateSkillQueuePage() {
  const shell = useOperatorShell();
  const store = useSkillsStore();

  const { data, isLoading, isError, error, refetch } = useSkillCandidates(shell.workspaceId, {
    queueStatus: store.filterQueueStatus ?? undefined,
  });

  const promoteMutation = usePromoteCandidate(shell.workspaceId);
  const rejectMutation = useRejectCandidate(shell.workspaceId);

  const candidates = data?.candidates ?? [];
  const selectedCandidate = candidates.find((c) => c.id === store.selectedCandidateId) ?? null;

  if (isLoading) {
    return <LoadingState label="Loading skill candidates..." />;
  }

  if (isError) {
    return (
      <ErrorState
        error={error}
        retry={() => void refetch()}
        title="Could not load skill candidates"
      />
    );
  }

  const readyCount = candidates.filter((c) => c.queueStatus === 'ready').length;
  const evaluatingCount = candidates.filter((c) => c.queueStatus === 'evaluating').length;

  return (
    <div className="operator-surface-page">
      <SurfaceIntro
        eyebrow="Skills / Candidate Queue"
        title="Candidate Queue"
        description="Skills awaiting evaluation and promotion. Review the manifest and rollout pipeline before promoting to the workspace."
        actions={
          <div className="operator-rail-status">
            <TopStatusPill label="Total" tone="neutral" value={String(candidates.length)} />
            <TopStatusPill label="Ready" tone="success" value={String(readyCount)} />
            <TopStatusPill label="Evaluating" tone="info" value={String(evaluatingCount)} />
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
          onChange={(e) => store.setFilterQueueStatus((e.target.value || null) as QueueStatus | null)}
          style={{ fontSize: '12px' }}
          value={store.filterQueueStatus ?? ''}
        >
          <option value="">All statuses</option>
          <option value="queued">Queued</option>
          <option value="evaluating">Evaluating</option>
          <option value="ready">Ready</option>
          <option value="promoted">Promoted</option>
          <option value="rejected">Rejected</option>
        </select>

        <select
          onChange={(e) => store.setFilterSelfModClass((e.target.value || null) as SelfModClass | null)}
          style={{ fontSize: '12px' }}
          value={store.filterSelfModClass ?? ''}
        >
          <option value="">All classes</option>
          <option value="C0">C0 — Read-only</option>
          <option value="C1">C1 — Config write</option>
          <option value="C2">C2 — Code write</option>
          <option value="C3">C3 — Full self-modification</option>
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
        {/* Left: candidate list */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', overflow: 'auto' }}>
          {candidates.length === 0 ? (
            <EmptyState
              compact
              title="No candidates"
              body="No skill candidates match the current filters."
            />
          ) : (
            candidates.map((candidate) => (
              <div
                key={candidate.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '10px 12px',
                  borderRadius: '8px',
                  border:
                    store.selectedCandidateId === candidate.id
                      ? '1px solid rgba(109, 211, 255, 0.2)'
                      : '1px solid rgba(158, 178, 198, 0.08)',
                  background:
                    store.selectedCandidateId === candidate.id
                      ? 'rgba(109, 211, 255, 0.08)'
                      : 'transparent',
                  cursor: 'pointer',
                }}
                onClick={() => store.setSelectedCandidate(candidate.id)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    store.setSelectedCandidate(candidate.id);
                  }
                }}
              >
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--operator-text)' }}>
                    {candidate.name}
                  </span>
                  <span style={{ fontSize: '11px', color: 'var(--operator-text-muted)' }}>
                    {candidate.version} · {candidate.selfModClass}
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
                  {candidate.queueStatus}
                </span>
              </div>
            ))
          )}
        </div>

        {/* Right: detail panel */}
        <div style={{ borderLeft: '1px solid rgba(158, 178, 198, 0.1)', paddingLeft: '16px', overflow: 'auto' }}>
          {selectedCandidate ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--operator-text)', margin: 0 }}>
                {selectedCandidate.name}
              </h3>
              <SkillManifestPanel skill={selectedCandidate} />
              <CanaryRolloutPanel candidate={selectedCandidate} />

              {selectedCandidate.queueStatus === 'ready' ? (
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    className="operator-button primary"
                    disabled={promoteMutation.isPending}
                    onClick={() => void promoteMutation.mutate(selectedCandidate.id)}
                    type="button"
                  >
                    {promoteMutation.isPending ? 'Promoting…' : 'Promote skill'}
                  </button>
                  <button
                    className="operator-button danger"
                    disabled={rejectMutation.isPending}
                    onClick={() =>
                      void rejectMutation.mutate({
                        candidateId: selectedCandidate.id,
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
              Select a candidate to view details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
