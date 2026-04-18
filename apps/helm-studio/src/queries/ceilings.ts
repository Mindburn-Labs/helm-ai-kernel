import { useQuery } from '@tanstack/react-query';
import type { CeilingSet } from '../types/ceiling';

export function useCeilingSet(ceilingSetId: string) {
  return useQuery({
    queryKey: ['legacy', 'ceiling', ceilingSetId],
    queryFn: async (): Promise<CeilingSet | null> => {
      throw new Error('Ceiling sets are folded into active policy and have no standalone live endpoint.');
    },
    enabled: false,
  });
}
