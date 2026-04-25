import { useParams } from 'react-router-dom';
import { useRun, useRunReceipts } from '../operator/hooks';

export function useEvidencePack(id: string) {
  const params = useParams();
  const runQuery = useRun(params.workspaceId ?? '', id);
  const receiptsQuery = useRunReceipts(params.workspaceId ?? '', id);

  return {
    ...runQuery,
    data: runQuery.data
      ? {
          id,
          sources: receiptsQuery.data ?? [],
          truthState: runQuery.data.evidence_pack_hash ? 'attested' : 'stale',
        }
      : undefined,
  };
}
