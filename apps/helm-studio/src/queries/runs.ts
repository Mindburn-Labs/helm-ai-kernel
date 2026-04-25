import { useParams } from 'react-router-dom';
import { useRuns as useWorkspaceRuns } from '../operator/hooks';

export function useRuns(workspaceId?: string) {
  const params = useParams();
  return useWorkspaceRuns(workspaceId ?? params.workspaceId ?? '');
}
