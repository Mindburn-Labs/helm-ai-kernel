import { useQuery } from '@tanstack/react-query';

export function useConnectors() {
  return useQuery({
    queryKey: ['legacy', 'connectors'],
    queryFn: async (): Promise<Array<{ id: string; status: string }>> => {
      throw new Error('Connector health is not a first-class live surface in the current HELM operator shell.');
    },
    enabled: false,
  });
}
