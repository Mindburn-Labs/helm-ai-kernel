import { useOperatorShell } from '../../../operator/layout';
import {
  EmptyState,
  ErrorState,
  LoadingState,
  SurfaceIntro,
  TopStatusPill,
} from '../../../operator/components';
import { useEvidencePacks, useStartExport } from '../hooks';
import { useEvidenceStore } from '../store';
import { ReplayLaunchPanel } from '../components/ReplayLaunchPanel';
import type { ExportFormat, ExportStatus } from '../types';

export function EvidencePackExportPage() {
  const shell = useOperatorShell();
  const store = useEvidenceStore();

  const { data, isLoading, isError, error, refetch } = useEvidencePacks(
    shell.workspaceId,
    { status: store.filterStatus ?? undefined },
  );

  const exportMutation = useStartExport(shell.workspaceId);

  const jobs = data?.packs ?? [];

  if (isLoading) {
    return <LoadingState label="Loading evidence export jobs..." />;
  }

  if (isError) {
    return (
      <ErrorState
        error={error}
        retry={() => void refetch()}
        title="Could not load evidence export jobs"
      />
    );
  }

  const pendingCount = jobs.filter((j) => j.status === 'pending').length;
  const completedCount = jobs.filter((j) => j.status === 'completed').length;
  const failedCount = jobs.filter((j) => j.status === 'failed').length;

  return (
    <div className="operator-surface-page">
      <SurfaceIntro
        eyebrow="Evidence / Export"
        title="Evidence Pack Export"
        description="Export cryptographically verifiable evidence packs for audit, legal discovery, or replay. All exports use JCS canonicalization."
        actions={
          <div className="operator-rail-status">
            <TopStatusPill label="Pending" tone="info" value={String(pendingCount)} />
            <TopStatusPill label="Completed" tone="success" value={String(completedCount)} />
            <TopStatusPill
              label="Failed"
              tone={failedCount > 0 ? 'danger' : 'neutral'}
              value={String(failedCount)}
            />
          </div>
        }
      />

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 320px',
          gap: '20px',
          marginBottom: '20px',
        }}
      >
        <ReplayLaunchPanel
          onLaunch={(runIds) =>
            void exportMutation.mutate({
              format: store.exportFormat,
              runIds,
            })
          }
          isLaunching={exportMutation.isPending}
        />

        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <span style={{ fontSize: '10px', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--operator-text-muted)' }}>
            Export format
          </span>
          <select
            onChange={(e) => store.setExportFormat(e.target.value as ExportFormat)}
            style={{ fontSize: '12px' }}
            value={store.exportFormat}
          >
            <option value="json">JSON (JCS canonicalized)</option>
            <option value="protobuf">Protobuf (binary)</option>
          </select>
        </div>
      </div>

      <div style={{ marginTop: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '0 0 12px' }}>
          <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--operator-text)' }}>
            Export jobs
          </span>
          <select
            onChange={(e) => store.setFilterStatus((e.target.value || null) as ExportStatus | null)}
            style={{ fontSize: '12px' }}
            value={store.filterStatus ?? ''}
          >
            <option value="">All statuses</option>
            <option value="pending">Pending</option>
            <option value="exporting">Exporting</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
          </select>
        </div>

        {jobs.length === 0 ? (
          <EmptyState
            compact
            title="No export jobs"
            body="Use the replay launcher above to create an evidence pack export job."
          />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {jobs.map((job) => (
              <div
                key={job.id}
                style={{
                  padding: '10px 14px',
                  borderRadius: '8px',
                  border: '1px solid rgba(158, 178, 198, 0.1)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                }}
              >
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--operator-text)' }}>
                    {job.runIds.length} run{job.runIds.length !== 1 ? 's' : ''} · {job.format.toUpperCase()}
                  </span>
                  <span style={{ fontSize: '11px', color: 'var(--operator-text-muted)' }}>
                    {new Date(job.createdAt).toLocaleString()}
                    {job.completedAt ? ` → ${new Date(job.completedAt).toLocaleString()}` : ''}
                  </span>
                </div>

                <span
                  style={{
                    fontSize: '10px',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                    background:
                      job.status === 'completed'
                        ? 'rgba(80, 220, 120, 0.1)'
                        : job.status === 'failed'
                          ? 'rgba(255, 100, 100, 0.1)'
                          : 'rgba(109, 211, 255, 0.08)',
                    color:
                      job.status === 'completed'
                        ? 'rgba(80, 220, 120, 0.9)'
                        : job.status === 'failed'
                          ? 'var(--operator-tone-danger)'
                          : 'rgba(109, 211, 255, 0.9)',
                  }}
                >
                  {job.status}
                </span>

                {job.outputRef ? (
                  <code style={{ fontSize: '10px', color: 'var(--operator-text-muted)' }}>
                    {job.outputRef.slice(0, 24)}…
                  </code>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
