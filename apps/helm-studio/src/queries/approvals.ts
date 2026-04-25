import { useParams } from 'react-router-dom';
import { useApproval as useWorkspaceApproval } from '../operator/hooks';
import type { ApprovalCeremonyState } from '../types/approval';

export function useApproval(approvalId: string) {
  const params = useParams();
  const query = useWorkspaceApproval(params.workspaceId ?? '', approvalId);

  return {
    ...query,
    data: query.data
      ? ({
          approvalId: query.data.id,
          intentHash: query.data.intent_hash,
          uiSummaryHash: query.data.summary_hash,
          timeLockRemainingMs: Math.max(query.data.timelock_seconds, 0) * 1000,
          reentryRequired: query.data.status === 'pending',
          holdDurationMs: query.data.min_hold_seconds * 1000,
          truthState: query.data.status === 'pending' ? 'pending' : 'active',
        } satisfies ApprovalCeremonyState)
      : undefined,
  };
}
