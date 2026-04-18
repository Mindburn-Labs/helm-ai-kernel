import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '../api/http';
import { controlplaneApi } from '../api/controlplane';
import type {
  ApprovalRecord,
  FrontendChatResponse,
  GoalEnvelope,
  PolicyDraft,
  PolicyVersion,
  PublicApprovalResponse,
  PublicEvidenceResponse,
  PublicVerificationResponse,
  ResearchRunRecord,
  ReplayManifest,
  RunRecord,
  SimulationRecord,
  ToolSurfaceGraph,
} from '../api/types';
import type { WorkspaceContext } from '../types/domain';
import { mergeWorkspaces } from './model';

const keys = {
  session: ['operator', 'session'] as const,
  workspaces: ['operator', 'workspaces'] as const,
  workspace: (workspaceId: string) => ['operator', 'workspace', workspaceId] as const,
  runs: (workspaceId: string) => ['operator', 'runs', workspaceId] as const,
  run: (workspaceId: string, runId: string) => ['operator', 'run', workspaceId, runId] as const,
  approvals: (workspaceId: string) => ['operator', 'approvals', workspaceId] as const,
  approval: (workspaceId: string, approvalId: string) =>
    ['operator', 'approval', workspaceId, approvalId] as const,
  graphs: (workspaceId: string) => ['operator', 'graphs', workspaceId] as const,
  activePolicy: (workspaceId: string) => ['operator', 'policy', 'active', workspaceId] as const,
  simulations: (workspaceId: string) => ['operator', 'simulations', workspaceId] as const,
  replays: (workspaceId: string) => ['operator', 'replays', workspaceId] as const,
  tasks: (workspaceId: string) => ['operator', 'tasks', workspaceId] as const,
  goal: ['operator', 'goal', 'active'] as const,
  researchMissions: (workspaceId: string) => ['operator', 'research', 'missions', workspaceId] as const,
  researchRuns: (workspaceId: string) => ['operator', 'research', 'runs', workspaceId] as const,
  researchSources: (workspaceId: string) => ['operator', 'research', 'sources', workspaceId] as const,
  researchPublications: (workspaceId: string) => ['operator', 'research', 'publications', workspaceId] as const,
  researchOverrides: (workspaceId: string) => ['operator', 'research', 'overrides', workspaceId] as const,
  researchFeed: (workspaceId: string) => ['operator', 'research', 'feed', workspaceId] as const,
  publicVerify: (receiptId: string) => ['public', 'verify', receiptId] as const,
  publicEvidence: (bundleId: string) => ['public', 'evidence', bundleId] as const,
  publicApproval: (approvalId: string) => ['public', 'approval', approvalId] as const,
};

export function useSession() {
  return useQuery({
    queryKey: keys.session,
    queryFn: async () => {
      try {
        return await controlplaneApi.getSession();
      } catch (error) {
        if (isIgnorableControlplaneError(error)) {
          return null;
        }
        throw error;
      }
    },
  });
}

export function useOperatorWorkspaces() {
  return useQuery({
    queryKey: keys.workspaces,
    queryFn: async (): Promise<WorkspaceContext[]> => {
      const [studioResult, controlplaneResult] = await Promise.allSettled([
        controlplaneApi.listStudioWorkspaces(),
        controlplaneApi.listWorkspaces(),
      ]);

      const studioWorkspaces =
        studioResult.status === 'fulfilled' ? studioResult.value : [];
      const controlplaneWorkspaces =
        controlplaneResult.status === 'fulfilled' ? controlplaneResult.value : [];

      return mergeWorkspaces(studioWorkspaces, controlplaneWorkspaces);
    },
  });
}

export function useWorkspace(workspaceId: string) {
  return useQuery({
    queryKey: keys.workspace(workspaceId),
    enabled: Boolean(workspaceId),
    queryFn: async (): Promise<WorkspaceContext | null> => {
      try {
        return await controlplaneApi.getStudioWorkspace(workspaceId);
      } catch (error) {
        if (isNotFound(error)) {
          const workspaces = await controlplaneApi.listWorkspaces().catch(() => []);
          return workspaces.find((workspace) => workspace.id === workspaceId) ?? null;
        }
        throw error;
      }
    },
  });
}

export function useRuns(workspaceId: string) {
  return useQuery({
    queryKey: keys.runs(workspaceId),
    enabled: Boolean(workspaceId),
    queryFn: () => controlplaneApi.listRuns(workspaceId),
  });
}

export function useRun(workspaceId: string, runId: string) {
  return useQuery({
    queryKey: keys.run(workspaceId, runId),
    enabled: Boolean(workspaceId && runId),
    queryFn: async (): Promise<RunRecord | null> => {
      try {
        return await controlplaneApi.getRun(workspaceId, runId);
      } catch (error) {
        if (isNotFound(error)) {
          return null;
        }
        throw error;
      }
    },
  });
}

export function useRunReceipts(workspaceId: string, runId: string) {
  return useQuery({
    queryKey: [...keys.run(workspaceId, runId), 'receipts'],
    enabled: Boolean(workspaceId && runId),
    queryFn: () => controlplaneApi.listRunReceipts(workspaceId, runId),
  });
}

export function useApprovals(workspaceId: string) {
  return useQuery({
    queryKey: keys.approvals(workspaceId),
    enabled: Boolean(workspaceId),
    queryFn: () => controlplaneApi.listApprovals(workspaceId),
  });
}

export function useApproval(workspaceId: string, approvalId: string) {
  return useQuery({
    queryKey: keys.approval(workspaceId, approvalId),
    enabled: Boolean(workspaceId && approvalId),
    queryFn: async (): Promise<ApprovalRecord | null> => {
      try {
        return await controlplaneApi.getApproval(workspaceId, approvalId);
      } catch (error) {
        if (isNotFound(error)) {
          return null;
        }
        throw error;
      }
    },
  });
}

export function useGraphs(workspaceId: string) {
  return useQuery({
    queryKey: keys.graphs(workspaceId),
    enabled: Boolean(workspaceId),
    queryFn: () => controlplaneApi.listToolSurfaces(workspaceId),
  });
}

export function useActivePolicy(workspaceId: string) {
  return useQuery({
    queryKey: keys.activePolicy(workspaceId),
    enabled: Boolean(workspaceId),
    queryFn: async (): Promise<PolicyVersion | null> => {
      try {
        return await controlplaneApi.getActivePolicy(workspaceId);
      } catch (error) {
        if (isNotFound(error)) {
          return null;
        }
        throw error;
      }
    },
  });
}

export function useSimulations(workspaceId: string) {
  return useQuery({
    queryKey: keys.simulations(workspaceId),
    enabled: Boolean(workspaceId),
    queryFn: () => controlplaneApi.listSimulations(workspaceId),
  });
}

export function useReplays(workspaceId: string) {
  return useQuery({
    queryKey: keys.replays(workspaceId),
    enabled: Boolean(workspaceId),
    queryFn: async (): Promise<ReplayManifest[]> => {
      const replays = await controlplaneApi.listPublicReplays();
      return replays.filter((replay) => replay.workspace_id === workspaceId);
    },
  });
}

export function useActiveGoal() {
  return useQuery({
    queryKey: keys.goal,
    queryFn: async (): Promise<GoalEnvelope['goal']> => {
      try {
        const result = await controlplaneApi.getActiveGoal();
        return result.goal;
      } catch (error) {
        if (isIgnorableControlplaneError(error)) {
          return null;
        }
        throw error;
      }
    },
  });
}

export function usePublicVerification(receiptId: string) {
  return useQuery({
    queryKey: keys.publicVerify(receiptId),
    enabled: Boolean(receiptId),
    queryFn: () => controlplaneApi.getPublicVerification(receiptId),
  });
}

export function usePublicEvidence(bundleId: string) {
  return useQuery({
    queryKey: keys.publicEvidence(bundleId),
    enabled: Boolean(bundleId),
    queryFn: () => controlplaneApi.getPublicEvidence(bundleId),
  });
}

export function usePublicApproval(approvalId: string) {
  return useQuery({
    queryKey: keys.publicApproval(approvalId),
    enabled: Boolean(approvalId),
    queryFn: () => controlplaneApi.getPublicApproval(approvalId),
  });
}

export function useResearchRuns(workspaceId: string) {
  return useQuery({
    queryKey: keys.researchRuns(workspaceId),
    enabled: Boolean(workspaceId),
    queryFn: (): Promise<ResearchRunRecord[]> => controlplaneApi.listResearchRuns(workspaceId),
  });
}

export function useCreateResearchMission(workspaceId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (input: {
      title: string;
      thesis: string;
      mode: string;
      missionClass: string;
      publicationClass: string;
      topics?: string[];
      querySeeds?: string[];
    }) =>
      controlplaneApi.createResearchMission({
        workspaceId,
        ...input,
      }),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: keys.researchMissions(workspaceId) }),
        queryClient.invalidateQueries({ queryKey: keys.researchRuns(workspaceId) }),
        queryClient.invalidateQueries({ queryKey: keys.researchPublications(workspaceId) }),
        queryClient.invalidateQueries({ queryKey: keys.researchFeed(workspaceId) }),
      ]);
    },
  });
}

export function useCreateWorkspace() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (input: {
      name: string;
      mode: string;
      profile: string;
      runtimeTemplateId?: string;
      tenantId?: string;
      edition?: string;
      offerCode?: string;
      plan?: string;
    }) => {
      const workspace = await controlplaneApi.createStudioWorkspace({
        name: input.name,
        mode: input.mode,
        profile: input.profile,
        runtimeTemplateId: input.runtimeTemplateId,
      });

      let provisioningState: { status: string; workspace_id?: string } | null = null;
      if (input.tenantId) {
        provisioningState = await controlplaneApi
          .provisionWorkspace({
            tenantId: input.tenantId,
            workspaceName: input.name,
            edition: input.edition ?? 'oss',
            offerCode: input.offerCode ?? 'oss-free',
            plan: input.plan ?? 'free',
          })
          .catch(() => null);
      }

      return { workspace, provisioningState };
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: keys.workspaces });
    },
  });
}

export function useSubmitRun(workspaceId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (input: { templateId?: string; plan?: Record<string, unknown> }) =>
      controlplaneApi.submitRun({
        workspaceId,
        templateId: input.templateId,
        plan: input.plan,
      }),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: keys.runs(workspaceId) }),
        queryClient.invalidateQueries({ queryKey: keys.approvals(workspaceId) }),
      ]);
    },
  });
}

export function useResolveApproval(workspaceId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (input: {
      approvalId: string;
      decision: 'APPROVE' | 'DENY';
      approverId: string;
      reason?: string;
    }) =>
      controlplaneApi.resolveApproval({
        workspaceId,
        approvalId: input.approvalId,
        decision: input.decision,
        approverId: input.approverId,
        reason: input.reason,
      }),
    onSuccess: async (_, variables) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: keys.approvals(workspaceId) }),
        queryClient.invalidateQueries({ queryKey: keys.approval(workspaceId, variables.approvalId) }),
        queryClient.invalidateQueries({ queryKey: keys.runs(workspaceId) }),
      ]);
    },
  });
}

export function useImportToolSurface(workspaceId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (input: {
      sourceType: string;
      sourceUri?: string;
      manifest: Array<Record<string, unknown>>;
    }) =>
      controlplaneApi.importToolSurface({
        workspaceId,
        sourceType: input.sourceType,
        sourceUri: input.sourceUri,
        manifest: input.manifest,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: keys.graphs(workspaceId) });
    },
  });
}

export function useDraftPolicy(workspaceId: string) {
  return useMutation({
    mutationFn: (input: {
      toolSurfaceId: string;
      objective: string;
      constraints: string[];
      modelAdapter?: string;
    }) =>
      controlplaneApi.draftPolicy({
        workspaceId,
        toolSurfaceId: input.toolSurfaceId,
        objective: input.objective,
        constraints: input.constraints,
        modelAdapter: input.modelAdapter,
      }),
  });
}

export function useCompilePolicy(workspaceId: string) {
  return useMutation({
    mutationFn: (draftId: string) => controlplaneApi.compilePolicy(workspaceId, draftId),
  });
}

export function useActivatePolicy(workspaceId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (versionId: string) => controlplaneApi.activatePolicy(workspaceId, versionId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: keys.activePolicy(workspaceId) });
    },
  });
}

export function useSubmitSimulation(workspaceId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (input: { templateId: string; scope: string }) =>
      controlplaneApi.submitSimulation({
        workspaceId,
        templateId: input.templateId,
        scope: input.scope,
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: keys.simulations(workspaceId) });
    },
  });
}

export function useGenerateExport(workspaceId: string) {
  return useMutation({
    mutationFn: () => controlplaneApi.generateExport(workspaceId),
  });
}

export function useVerifyReceipt() {
  return useMutation({
    mutationFn: (receipt: NonNullable<RunRecord['receipts']>[number]) =>
      controlplaneApi.verifyReceipt(receipt),
  });
}

export function useSendChat() {
  return useMutation({
    mutationFn: (input: {
      message: string;
      conversationId: string;
      orgId?: string;
      history: Array<{ role: string; content: string }>;
    }): Promise<FrontendChatResponse> => controlplaneApi.sendChat(input),
  });
}

export function useAdvanceGoal() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (goalId: string) => controlplaneApi.advanceGoal(goalId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: keys.goal });
    },
  });
}

export function useApproveGoalBlocker() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (input: { goalId: string; blockerId: string }) =>
      controlplaneApi.approveGoalBlocker(input.goalId, input.blockerId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: keys.goal });
    },
  });
}

export function useTasks(workspaceId: string) {
  return useQuery({
    queryKey: keys.tasks(workspaceId),
    enabled: Boolean(workspaceId),
    queryFn: () => controlplaneApi.listTasks(workspaceId),
  });
}

export function useCreateTask(workspaceId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (input: {
      label: string;
      templateId?: string;
      plan?: Record<string, unknown>;
      cronExpr?: string;
      scheduledAt?: string;
      maxRetries?: number;
      effectClass?: string;
      policyHash?: string;
    }) =>
      controlplaneApi.createTask({
        workspaceId,
        ...input,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: keys.tasks(workspaceId) });
    },
  });
}

export function usePauseTask(workspaceId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (taskId: string) => controlplaneApi.pauseTask(workspaceId, taskId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: keys.tasks(workspaceId) });
    },
  });
}

export function useResumeTask(workspaceId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (taskId: string) => controlplaneApi.resumeTask(workspaceId, taskId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: keys.tasks(workspaceId) });
    },
  });
}

export function useCancelTask(workspaceId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (taskId: string) => controlplaneApi.cancelTask(workspaceId, taskId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: keys.tasks(workspaceId) });
    },
  });
}

export type OperatorMutationResult =
  | PolicyDraft
  | PolicyVersion
  | PublicVerificationResponse
  | PublicEvidenceResponse
  | PublicApprovalResponse
  | ToolSurfaceGraph
  | SimulationRecord
  | ApprovalRecord
  | RunRecord;

function isIgnorableControlplaneError(error: unknown): boolean {
  return isApiStatus(error, 401) || isApiStatus(error, 404) || isApiStatus(error, 501);
}

function isNotFound(error: unknown): boolean {
  return isApiStatus(error, 404);
}

function isApiStatus(error: unknown, status: number): boolean {
  return error instanceof ApiError && error.status === status;
}
