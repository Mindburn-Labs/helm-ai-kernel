import { useEffect, useState } from 'react';

/** Counts down from a timelock deadline in milliseconds. Shows expired when done. */
export function TimelockCountdown({
  timelockMs,
  startedAtMs,
}: {
  timelockMs: number;
  startedAtMs: number;
}) {
  const [remaining, setRemaining] = useState(() => {
    const deadline = startedAtMs + timelockMs;
    return Math.max(0, deadline - Date.now());
  });

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      const deadline = startedAtMs + timelockMs;
      setRemaining(Math.max(0, deadline - Date.now()));
    }, 1_000);
    return () => window.clearInterval(intervalId);
  }, [timelockMs, startedAtMs]);

  if (remaining === 0) {
    return (
      <span
        style={{
          fontSize: '11px',
          fontWeight: 700,
          color: 'var(--operator-tone-danger)',
          padding: '2px 6px',
          borderRadius: '4px',
          background: 'rgba(255, 100, 100, 0.1)',
        }}
      >
        EXPIRED
      </span>
    );
  }

  const totalSeconds = Math.floor(remaining / 1_000);
  const hours = Math.floor(totalSeconds / 3_600);
  const minutes = Math.floor((totalSeconds % 3_600) / 60);
  const seconds = totalSeconds % 60;

  const formatted =
    hours > 0
      ? `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`
      : `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;

  const tone = remaining < 60_000 ? 'danger' : remaining < 300_000 ? 'warning' : 'neutral';

  return (
    <span
      style={{
        fontSize: '11px',
        fontWeight: 700,
        fontVariantNumeric: 'tabular-nums',
        color:
          tone === 'danger'
            ? 'var(--operator-tone-danger)'
            : tone === 'warning'
              ? 'var(--operator-tone-warning)'
              : 'var(--operator-text-muted)',
        padding: '2px 6px',
        borderRadius: '4px',
        background:
          tone === 'danger'
            ? 'rgba(255, 100, 100, 0.1)'
            : tone === 'warning'
              ? 'rgba(255, 200, 50, 0.08)'
              : 'rgba(158, 178, 198, 0.08)',
      }}
    >
      {formatted}
    </span>
  );
}
