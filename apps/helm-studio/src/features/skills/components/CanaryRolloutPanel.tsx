import type { SkillCandidate } from '../types';

/** Shows the current stage in the canary rollout pipeline for a skill candidate. */
export function CanaryRolloutPanel({ candidate }: { candidate: SkillCandidate }) {
  const stages: SkillCandidate['queueStatus'][] = [
    'queued',
    'evaluating',
    'ready',
    'promoted',
  ];

  const currentIndex = stages.indexOf(candidate.queueStatus);
  const isRejected = candidate.queueStatus === 'rejected';

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        padding: '12px',
        borderRadius: '8px',
        border: '1px solid rgba(158, 178, 198, 0.12)',
        background: 'rgba(158, 178, 198, 0.04)',
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
        Canary Rollout Pipeline
      </span>

      {isRejected ? (
        <span style={{ fontSize: '12px', color: 'var(--operator-tone-danger)', fontWeight: 600 }}>
          Candidate was rejected.
        </span>
      ) : (
        <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
          {stages.map((stage, index) => {
            const isDone = index < currentIndex;
            const isActive = index === currentIndex;

            return (
              <div key={stage} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <div
                  style={{
                    padding: '3px 8px',
                    borderRadius: '4px',
                    fontSize: '10px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                    background: isActive
                      ? 'rgba(109, 211, 255, 0.15)'
                      : isDone
                        ? 'rgba(80, 220, 120, 0.12)'
                        : 'rgba(158, 178, 198, 0.06)',
                    color: isActive
                      ? 'var(--operator-text)'
                      : isDone
                        ? 'rgba(80, 220, 120, 0.9)'
                        : 'var(--operator-text-muted)',
                    border: isActive
                      ? '1px solid rgba(109, 211, 255, 0.25)'
                      : '1px solid transparent',
                  }}
                >
                  {stage}
                </div>
                {index < stages.length - 1 ? (
                  <span style={{ fontSize: '10px', color: 'var(--operator-text-muted)' }}>→</span>
                ) : null}
              </div>
            );
          })}
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
        <span style={{ color: 'var(--operator-text-soft)' }}>Evaluation verdict</span>
        <span
          style={{
            fontWeight: 700,
            color:
              candidate.evaluationVerdict === 'pass'
                ? 'rgba(80, 220, 120, 0.9)'
                : candidate.evaluationVerdict === 'fail'
                  ? 'var(--operator-tone-danger)'
                  : 'var(--operator-tone-warning)',
          }}
        >
          {candidate.evaluationVerdict.toUpperCase()}
        </span>
      </div>
    </div>
  );
}
