import { formatRelativeTime } from '../../../operator/model';
import { PolicyVerdictBadge } from './PolicyVerdictBadge';
import { RiskClassPill } from './RiskClassPill';
import type { ActionProposalRecord } from '../types';

/** Compact row for the proposal list. Includes batch checkbox, summary, risk pill, verdict badge, and time. */
export function ProposalRow({
  proposal,
  isSelected,
  isBatchSelected,
  onSelect,
  onBatchToggle,
}: {
  proposal: ActionProposalRecord;
  isSelected: boolean;
  isBatchSelected: boolean;
  onSelect: () => void;
  onBatchToggle: () => void;
}) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        padding: '10px 12px',
        borderRadius: '8px',
        background: isSelected ? 'rgba(109, 211, 255, 0.08)' : 'transparent',
        border: isSelected
          ? '1px solid rgba(109, 211, 255, 0.2)'
          : '1px solid rgba(158, 178, 198, 0.08)',
        cursor: 'pointer',
        transition: 'background 0.1s',
      }}
    >
      <input
        checked={isBatchSelected}
        onChange={(e) => {
          e.stopPropagation();
          onBatchToggle();
        }}
        onClick={(e) => e.stopPropagation()}
        style={{ flexShrink: 0, cursor: 'pointer' }}
        type="checkbox"
      />

      <div
        onClick={onSelect}
        role="button"
        style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '4px', minWidth: 0 }}
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onSelect();
          }
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span
            style={{
              fontSize: '13px',
              fontWeight: 600,
              color: 'var(--operator-text)',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              flex: 1,
            }}
          >
            {proposal.summary}
          </span>
          <RiskClassPill riskClass={proposal.risk_class} />
          <PolicyVerdictBadge verdict={proposal.policy_verdict} />
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '11px',
            color: 'var(--operator-text-soft)',
          }}
        >
          <span>{proposal.tool_name}</span>
          <span style={{ opacity: 0.4 }}>|</span>
          <span>{proposal.connector_id}</span>
          <span style={{ opacity: 0.4 }}>|</span>
          <span>{proposal.status}</span>
          <span style={{ marginLeft: 'auto' }}>{formatRelativeTime(proposal.created_at)}</span>
        </div>
      </div>
    </div>
  );
}
