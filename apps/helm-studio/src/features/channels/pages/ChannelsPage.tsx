import { useOperatorShell } from '../../../operator/layout';
import {
  EmptyState,
  ErrorState,
  LoadingState,
  SurfaceIntro,
  TopStatusPill,
} from '../../../operator/components';
import { useChannelSessions, useQuarantineSession } from '../hooks';
import { useChannelsStore } from '../store';
import { SessionRouterPanel } from '../components/SessionRouterPanel';
import { SuspiciousInputPanel } from '../components/SuspiciousInputPanel';
import { VoiceInboxPanel } from '../components/VoiceInboxPanel';
import type { ChannelType, SessionStatus } from '../types';

export function ChannelsPage() {
  const shell = useOperatorShell();
  const store = useChannelsStore();

  const { data, isLoading, isError, error, refetch } = useChannelSessions(shell.workspaceId, {
    channel: store.filterChannel ?? undefined,
    status: store.filterStatus ?? undefined,
  });

  const quarantineMutation = useQuarantineSession(shell.workspaceId);

  const sessions = data?.sessions ?? [];
  const selectedSession = sessions.find((s) => s.id === store.selectedSessionId) ?? null;

  if (isLoading) {
    return <LoadingState label="Loading channel sessions..." />;
  }

  if (isError) {
    return (
      <ErrorState
        error={error}
        retry={() => void refetch()}
        title="Could not load channel sessions"
      />
    );
  }

  const activeCount = sessions.filter((s) => s.status === 'active').length;
  const quarantinedCount = sessions.filter((s) => s.status === 'quarantined').length;

  return (
    <div className="operator-surface-page">
      <SurfaceIntro
        eyebrow="Channels"
        title="Channel Sessions"
        description="Active inbound channel sessions from Slack, Telegram, and Lark. Quarantine suspicious sessions or close them to prevent further processing."
        actions={
          <div className="operator-rail-status">
            <TopStatusPill label="Total" tone="neutral" value={String(sessions.length)} />
            <TopStatusPill label="Active" tone="success" value={String(activeCount)} />
            <TopStatusPill
              label="Quarantined"
              tone={quarantinedCount > 0 ? 'danger' : 'neutral'}
              value={String(quarantinedCount)}
            />
          </div>
        }
      />

      <VoiceInboxPanel sessionCount={0} />

      <div style={{ display: 'flex', gap: '10px', padding: '12px 0' }}>
        <select
          onChange={(e) => store.setFilterChannel((e.target.value || null) as ChannelType | null)}
          style={{ fontSize: '12px' }}
          value={store.filterChannel ?? ''}
        >
          <option value="">All channels</option>
          <option value="slack">Slack</option>
          <option value="telegram">Telegram</option>
          <option value="lark">Lark</option>
        </select>

        <select
          onChange={(e) => store.setFilterStatus((e.target.value || null) as SessionStatus | null)}
          style={{ fontSize: '12px' }}
          value={store.filterStatus ?? ''}
        >
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="quarantined">Quarantined</option>
          <option value="closed">Closed</option>
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
        {/* Left: session list */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', overflow: 'auto' }}>
          {sessions.length === 0 ? (
            <EmptyState compact title="No sessions" body="No channel sessions match the current filters." />
          ) : (
            sessions.map((session) => (
              <div
                key={session.id}
                style={{
                  padding: '10px 12px',
                  borderRadius: '8px',
                  border:
                    store.selectedSessionId === session.id
                      ? '1px solid rgba(109, 211, 255, 0.2)'
                      : session.status === 'quarantined'
                        ? '1px solid rgba(255, 100, 100, 0.2)'
                        : '1px solid rgba(158, 178, 198, 0.08)',
                  background:
                    store.selectedSessionId === session.id
                      ? 'rgba(109, 211, 255, 0.08)'
                      : 'transparent',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '3px',
                }}
                onClick={() => store.setSelectedSession(session.id)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    store.setSelectedSession(session.id);
                  }
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--operator-text)' }}>
                    {session.senderId}
                  </span>
                  <span
                    style={{
                      fontSize: '10px',
                      padding: '1px 5px',
                      borderRadius: '3px',
                      background: 'rgba(158, 178, 198, 0.08)',
                      color: 'var(--operator-text-muted)',
                      textTransform: 'uppercase',
                      fontWeight: 700,
                    }}
                  >
                    {session.channel}
                  </span>
                  {session.status === 'quarantined' ? (
                    <span
                      style={{
                        fontSize: '10px',
                        padding: '1px 5px',
                        borderRadius: '3px',
                        background: 'rgba(255, 100, 100, 0.1)',
                        color: 'var(--operator-tone-danger)',
                        textTransform: 'uppercase',
                        fontWeight: 700,
                      }}
                    >
                      QUARANTINED
                    </span>
                  ) : null}
                </div>
                <span style={{ fontSize: '11px', color: 'var(--operator-text-muted)' }}>
                  {new Date(session.createdAt).toLocaleString()}
                </span>
              </div>
            ))
          )}
        </div>

        {/* Right: detail panel */}
        <div style={{ borderLeft: '1px solid rgba(158, 178, 198, 0.1)', paddingLeft: '16px', overflow: 'auto' }}>
          {selectedSession ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <SuspiciousInputPanel session={selectedSession} />
              <SessionRouterPanel session={selectedSession} />

              {selectedSession.status === 'active' ? (
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    className="operator-button danger"
                    disabled={quarantineMutation.isPending}
                    onClick={() =>
                      void quarantineMutation.mutate({
                        sessionId: selectedSession.id,
                        reason: 'Quarantined by operator',
                      })
                    }
                    type="button"
                  >
                    Quarantine
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
              Select a session to view details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
