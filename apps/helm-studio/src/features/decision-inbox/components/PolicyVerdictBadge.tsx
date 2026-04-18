import type { PolicyVerdict } from '../types';

const VERDICT_BG: Record<PolicyVerdict, string> = {
  ALLOW: 'rgba(121, 216, 166, 0.15)',
  DENY: 'rgba(255, 122, 112, 0.18)',
  ESCALATE: 'rgba(255, 185, 104, 0.15)',
  HELD: 'rgba(158, 178, 198, 0.12)',
};

const VERDICT_COLOR: Record<PolicyVerdict, string> = {
  ALLOW: 'var(--operator-success)',
  DENY: 'var(--operator-danger)',
  ESCALATE: 'var(--operator-warning)',
  HELD: 'var(--operator-text-muted)',
};

export function PolicyVerdictBadge({ verdict }: { verdict: PolicyVerdict }) {
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: '6px',
        fontSize: '11px',
        fontWeight: 600,
        letterSpacing: '0.04em',
        background: VERDICT_BG[verdict] ?? 'rgba(158, 178, 198, 0.08)',
        color: VERDICT_COLOR[verdict] ?? 'var(--operator-text-muted)',
        whiteSpace: 'nowrap',
      }}
    >
      {verdict}
    </span>
  );
}
