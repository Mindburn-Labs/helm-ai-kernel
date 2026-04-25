/** Placeholder panel for voice channel inbox. Renders a notice when no voice sessions are active. */
export function VoiceInboxPanel({ sessionCount }: { sessionCount: number }) {
  return (
    <div
      style={{
        padding: '12px',
        borderRadius: '8px',
        border: '1px solid rgba(158, 178, 198, 0.12)',
        background: 'rgba(158, 178, 198, 0.04)',
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
      }}
    >
      <span
        style={{
          fontSize: '10px',
          fontWeight: 700,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          color: 'var(--operator-text-muted)',
        }}
      >
        Voice Inbox
      </span>
      {sessionCount === 0 ? (
        <p style={{ fontSize: '12px', color: 'var(--operator-text-muted)', margin: 0 }}>
          No active voice sessions. Voice routing is available once a telephony connector is installed.
        </p>
      ) : (
        <p style={{ fontSize: '12px', color: 'var(--operator-text-soft)', margin: 0 }}>
          {sessionCount} active voice session{sessionCount !== 1 ? 's' : ''}.
        </p>
      )}
    </div>
  );
}
