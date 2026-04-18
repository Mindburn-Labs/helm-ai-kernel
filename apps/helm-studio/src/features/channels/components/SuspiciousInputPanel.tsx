import type { ChannelSession } from '../types';

/** Warns when a session is quarantined due to suspicious input detection. */
export function SuspiciousInputPanel({ session }: { session: ChannelSession }) {
  if (session.status !== 'quarantined') {
    return null;
  }

  return (
    <div
      style={{
        padding: '12px',
        borderRadius: '8px',
        border: '1px solid rgba(255, 100, 100, 0.2)',
        background: 'rgba(255, 100, 100, 0.05)',
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
      }}
      role="alert"
    >
      <span
        style={{
          fontSize: '10px',
          fontWeight: 700,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          color: 'var(--operator-tone-danger)',
        }}
      >
        Suspicious Input Detected
      </span>
      <p style={{ fontSize: '12px', color: 'var(--operator-text-soft)', margin: 0 }}>
        This session has been quarantined. Messages from sender{' '}
        <code style={{ fontSize: '11px' }}>{session.senderId}</code> are being held pending review.
        No further processing will occur until the session is released or closed.
      </p>
    </div>
  );
}
