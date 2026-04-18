import { useQuery } from '@tanstack/react-query';

export function useIncident(id: string) {
  return useQuery({
    queryKey: ['legacy', 'incident', id],
    queryFn: async (): Promise<{ id: string; title: string; status: string } | null> => {
      throw new Error('Incident workbench is not backed by a live endpoint in the current HELM operator shell.');
    },
    enabled: false,
  });
}
