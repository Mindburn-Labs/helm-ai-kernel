import { useQuery } from '@tanstack/react-query';

export function useArtifact(artifactId: string) {
  return useQuery({
    queryKey: ['legacy', 'artifact', artifactId],
    queryFn: async (): Promise<{ id: string; type: string } | null> => {
      throw new Error('Artifact lookup has no live endpoint in the current HELM operator shell.');
    },
    enabled: false,
  });
}
