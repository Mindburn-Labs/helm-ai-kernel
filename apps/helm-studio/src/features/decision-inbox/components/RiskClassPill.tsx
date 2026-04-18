import type { RiskClass } from '../types';

const RISK_BG: Record<RiskClass, string> = {
  R0: 'rgba(109, 211, 255, 0.12)',
  R1: 'rgba(121, 216, 166, 0.15)',
  R2: 'rgba(255, 185, 104, 0.15)',
  R3: 'rgba(255, 122, 112, 0.18)',
};

const RISK_COLOR: Record<RiskClass, string> = {
  R0: 'var(--operator-accent)',
  R1: 'var(--operator-success)',
  R2: 'var(--operator-warning)',
  R3: 'var(--operator-danger)',
};

const RISK_LABEL: Record<RiskClass, string> = {
  R0: 'R0 Read-only',
  R1: 'R1 Internal',
  R2: 'R2 External',
  R3: 'R3 Critical',
};

export function RiskClassPill({ riskClass }: { riskClass: RiskClass }) {
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: '6px',
        fontSize: '11px',
        fontWeight: 600,
        letterSpacing: '0.04em',
        background: RISK_BG[riskClass] ?? 'rgba(158, 178, 198, 0.08)',
        color: RISK_COLOR[riskClass] ?? 'var(--operator-text-muted)',
        whiteSpace: 'nowrap',
      }}
    >
      {RISK_LABEL[riskClass] ?? riskClass}
    </span>
  );
}
