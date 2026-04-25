import { useState } from 'react';
import { useOperatorShell } from '../../../operator/layout';
import {
  EmptyState,
  ErrorState,
  LoadingState,
  SurfaceIntro,
  TopStatusPill,
} from '../../../operator/components';
import { useEvidenceReplay } from '../hooks';
import { useEvidenceStore } from '../store';

export function ProofGraphPage() {
  const shell = useOperatorShell();
  const store = useEvidenceStore();
  const [runIdInput, setRunIdInput] = useState('');

  const replayId = store.selectedRunId ?? '';
  const { data, isLoading, isError, error, refetch } = useEvidenceReplay(
    shell.workspaceId,
    replayId,
  );

  const replayData = data as { nodes?: Array<{ id: string; type: string; label: string; parentIds: string[]; hash: string; createdAt: string }> } | undefined;
  const nodes = replayData?.nodes ?? [];

  if (isLoading) {
    return <LoadingState label="Loading proof graph..." />;
  }

  if (isError) {
    return (
      <ErrorState
        error={error}
        retry={() => void refetch()}
        title="Could not load proof graph"
      />
    );
  }

  return (
    <div className="operator-surface-page">
      <SurfaceIntro
        eyebrow="Evidence / Proof Graph"
        title="Proof Graph"
        description="Causal DAG of execution steps for a given run. Each node is cryptographically hashed and links to its parent nodes for full auditability."
        actions={
          <div className="operator-rail-status">
            <TopStatusPill label="Nodes" tone="neutral" value={String(nodes.length)} />
          </div>
        }
      />

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '0 0 12px' }}>
        <input
          placeholder="Run ID to inspect..."
          style={{
            fontSize: '12px',
            padding: '6px 10px',
            borderRadius: '6px',
            border: '1px solid rgba(158, 178, 198, 0.2)',
            background: 'rgba(0, 0, 0, 0.2)',
            color: 'var(--operator-text)',
            minWidth: '280px',
          }}
          type="text"
          value={runIdInput}
          onChange={(e) => setRunIdInput(e.target.value)}
        />
        <button
          className="operator-button secondary"
          onClick={() => store.setSelectedRunId(runIdInput.trim() || null)}
          style={{ fontSize: '11px' }}
          type="button"
        >
          Load graph
        </button>
        {store.selectedRunId ? (
          <button
            className="operator-button ghost"
            onClick={() => {
              store.setSelectedRunId(null);
              setRunIdInput('');
            }}
            style={{ fontSize: '11px' }}
            type="button"
          >
            Clear
          </button>
        ) : null}
      </div>

      {nodes.length === 0 ? (
        <EmptyState
          title="No proof graph"
          body="Enter a run ID above to load its causal execution graph. Each node represents a verified execution step."
        />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {nodes.map((node) => (
            <div
              key={node.id}
              style={{
                padding: '10px 14px',
                borderRadius: '8px',
                border: '1px solid rgba(158, 178, 198, 0.1)',
                display: 'flex',
                flexDirection: 'column',
                gap: '4px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span
                  style={{
                    fontSize: '10px',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    background: 'rgba(109, 211, 255, 0.1)',
                    color: 'rgba(109, 211, 255, 0.9)',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                  }}
                >
                  {node.type}
                </span>
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--operator-text)' }}>
                  {node.label}
                </span>
              </div>
              <div style={{ display: 'flex', gap: '12px', fontSize: '11px', color: 'var(--operator-text-muted)' }}>
                <code>{node.hash.slice(0, 16)}…</code>
                {node.parentIds.length > 0 ? (
                  <span>
                    Parents: {node.parentIds.map((pid) => pid.slice(0, 8)).join(', ')}
                  </span>
                ) : (
                  <span style={{ fontStyle: 'italic' }}>root node</span>
                )}
                <span style={{ marginLeft: 'auto' }}>
                  {new Date(node.createdAt).toLocaleString()}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
