import { useParams } from 'react-router-dom';
import { useActivePolicy } from '../operator/hooks';

export function usePolicy(policyId: string) {
  const params = useParams();
  void policyId;
  return useActivePolicy(params.workspaceId ?? '');
}
