import { useState } from 'react';

/** Panel for selecting run IDs and launching a replay from evidence. */
export function ReplayLaunchPanel({
  onLaunch,
  isLaunching,
}: {
  onLaunch: (runIds: string[]) => void;
  isLaunching: boolean;
}) {
  const [runIdsInput, setRunIdsInput] = useState('');

  const handleLaunch = () => {
    const ids = runIdsInput
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (ids.length > 0) {
      onLaunch(ids);
    }
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
        gap: '10px',
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
        Replay Launcher
      </span>

      <p style={{ fontSize: '12px', color: 'var(--operator-text-soft)', margin: 0 }}>
        Enter run IDs (comma or newline separated) to export their evidence packs for replay.
      </p>

      <textarea
        placeholder="run-id-1, run-id-2, ..."
        rows={3}
        style={{
          resize: 'vertical',
          fontSize: '12px',
          padding: '8px',
          borderRadius: '6px',
          border: '1px solid rgba(158, 178, 198, 0.2)',
          background: 'rgba(0, 0, 0, 0.2)',
          color: 'var(--operator-text)',
          fontFamily: 'monospace',
        }}
        value={runIdsInput}
        onChange={(e) => setRunIdsInput(e.target.value)}
      />

      <button
        className="operator-button primary"
        disabled={isLaunching || !runIdsInput.trim()}
        onClick={handleLaunch}
        type="button"
      >
        {isLaunching ? 'Launching…' : 'Launch replay export'}
      </button>
    </div>
  );
}
