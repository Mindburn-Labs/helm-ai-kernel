import type { ChannelSession } from '../types';

/** Shows routing details for a channel session — channel type, sender, thread, and status. */
export function SessionRouterPanel({ session }: { session: ChannelSession }) {
  const channelColor: Record<string, string> = {
    slack: '#4A154B',
    telegram: '#229ED9',
    lark: '#1456F0',
  };

  return (
    <div
      style={{
        padding: '12px',
        borderRadius: '8px',
        border: '1px solid rgba(158, 178, 198, 0.12)',
        background: 'rgba(158, 178, 198, 0.04)',
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span
          style={{
            fontSize: '10px',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '0.08em',
            padding: '2px 7px',
            borderRadius: '4px',
            color: '#fff',
            background: channelColor[session.channel] ?? 'rgba(158, 178, 198, 0.2)',
          }}
        >
          {session.channel}
        </span>
        <span
          style={{
            fontSize: '10px',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            color:
              session.status === 'active'
                ? 'rgba(80, 220, 120, 0.9)'
                : session.status === 'quarantined'
                  ? 'var(--operator-tone-danger)'
                  : 'var(--operator-text-muted)',
          }}
        >
          {session.status}
        </span>
      </div>

      {[
        { label: 'Sender ID', value: session.senderId },
        ...(session.threadId ? [{ label: 'Thread ID', value: session.threadId }] : []),
        { label: 'Session ID', value: session.id },
        { label: 'Created', value: new Date(session.createdAt).toLocaleString() },
      ].map(({ label, value }) => (
        <div key={label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
          <span style={{ color: 'var(--operator-text-soft)' }}>{label}</span>
          <code style={{ fontSize: '11px', color: 'var(--operator-text)', fontWeight: 600 }}>
            {value}
          </code>
        </div>
      ))}
    </div>
  );
}
