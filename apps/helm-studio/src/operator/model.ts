import type {
  ApprovalRecord,
  GoalRecord,
  PolicyVersion,
  ReplayManifest,
  RunRecord,
  ToolSurfaceGraph,
} from '../api/types';
import type { WorkspaceContext, RiskLevel, Surface, TruthStage } from '../types/domain';
import type {
  ActivityItem,
  ArtifactRef,
  ExecutionPlan,
  ExecutionStep,
  StateSignal,
  TruthStamp,
} from '../types/operator';

export const SURFACE_ORDER: Surface[] = ['canvas', 'operate', 'research', 'govern', 'proof', 'chat'];

const SURFACE_LABELS: Record<Surface, string> = {
  canvas: 'Canvas',
  operate: 'Operate',
  research: 'Research',
  govern: 'Govern',
  proof: 'Proof',
  chat: 'Chat',
};

const RUNNING_STATES = new Set(['queued', 'running', 'allow', 'pending_approval']);
const BLOCKED_STATES = new Set(['pending_approval', 'deny', 'failed', 'blocked']);

export function getSurfaceLabel(surface: Surface): string {
  return SURFACE_LABELS[surface];
}

export function getSurfaceHref(workspaceId: string, surface: Surface): string {
  return `/workspaces/${workspaceId}/${surface}`;
}

export function getArtifactHref(workspaceId: string, artifact: ArtifactRef): string | undefined {
  if (artifact.href) {
    return artifact.href;
  }

  switch (artifact.type) {
    case 'graph':
      return getSurfaceHref(workspaceId, 'canvas');
    case 'run':
    case 'approval':
      return getSurfaceHref(workspaceId, 'operate');
    case 'policy':
      return getSurfaceHref(workspaceId, 'govern');
    case 'receipt':
    case 'evidence':
      return getSurfaceHref(workspaceId, 'proof');
    case 'goal':
      return getSurfaceHref(workspaceId, 'chat');
    default:
      return undefined;
  }
}

export function mergeWorkspaces(
  studioWorkspaces: WorkspaceContext[],
  controlplaneWorkspaces: WorkspaceContext[],
): WorkspaceContext[] {
  const byId = new Map<string, WorkspaceContext>();

  for (const workspace of controlplaneWorkspaces) {
    byId.set(workspace.id, workspace);
  }

  for (const workspace of studioWorkspaces) {
    const existing = byId.get(workspace.id);
    byId.set(workspace.id, {
      ...existing,
      ...workspace,
      source: existing?.source === 'controlplane' ? 'studio' : workspace.source ?? 'studio',
    });
  }

  return Array.from(byId.values()).sort((left, right) => {
    const leftTime = left.updatedAt ?? left.createdAt ?? '';
    const rightTime = right.updatedAt ?? right.createdAt ?? '';
    return rightTime.localeCompare(leftTime) || left.name.localeCompare(right.name);
  });
}

export function deriveRiskLevel(input: {
  effectClass?: string;
  status?: string;
  pendingApprovals?: number;
}): RiskLevel {
  if (input.effectClass === 'E4' || input.status === 'deny' || input.status === 'failed') {
    return 'critical';
  }
  if (
    input.effectClass === 'E3' ||
    input.status === 'pending_approval' ||
    (input.pendingApprovals ?? 0) > 0
  ) {
    return 'high';
  }
  if (input.effectClass === 'E2' || input.status === 'running' || input.status === 'queued') {
    return 'medium';
  }
  return 'low';
}

export function deriveRunTruth(run: RunRecord): TruthStamp {
  const stage: TruthStage =
    run.status === 'completed'
      ? 'verified'
      : run.status === 'pending_approval'
        ? 'blocked'
        : run.status === 'queued' || run.status === 'running'
          ? 'running'
          : run.status === 'deny'
            ? 'blocked'
            : 'approved';

  return {
    stage,
    label:
      run.status === 'pending_approval'
        ? 'Approval required'
        : run.status === 'completed'
          ? 'Receipts sealed'
          : run.status === 'deny'
            ? 'Denied by policy'
            : run.status,
    detail:
      run.reason_code ??
      run.verdict ??
      (run.status === 'completed'
        ? 'Execution and receipt chain completed.'
        : 'Execution is progressing under current policy.'),
  };
}

export function deriveApprovalTruth(approval: ApprovalRecord): TruthStamp {
  return {
    stage: approval.status === 'pending' ? 'proposed' : 'approved',
    label: approval.status === 'pending' ? 'Waiting for operator review' : approval.status,
    detail: approval.risk_summary || approval.action_summary,
  };
}

export function buildControlStrip(input: {
  runs: RunRecord[];
  approvals: ApprovalRecord[];
  goal: GoalRecord | null;
  activePolicy: PolicyVersion | null;
}): StateSignal[] {
  const running = input.runs.filter((run) => RUNNING_STATES.has(run.status)).length;
  const blocked = input.runs.filter((run) => BLOCKED_STATES.has(run.status)).length;
  const receiptCount = input.runs.reduce((count, run) => count + (run.receipts?.length ?? 0), 0);
  const risk = input.runs.reduce<RiskLevel>(
    (highest, run) => maxRisk(highest, deriveRiskLevel({ effectClass: run.effect_class, status: run.status })),
    deriveRiskLevel({ pendingApprovals: input.approvals.length }),
  );
  const blockers = input.goal?.blockers?.length ?? 0;

  return [
    {
      key: 'now',
      label: 'Now',
      value: running > 0 ? `${running} governed runs active` : 'No active execution',
      detail:
        running > 0
          ? 'Queue, execution, and proof state are live.'
          : 'The workspace is idle and ready for a new governed action.',
      tone: running > 0 ? 'info' : 'neutral',
    },
    {
      key: 'needs-you',
      label: 'Needs You',
      value:
        input.approvals.length > 0
          ? `${input.approvals.length} approval${input.approvals.length === 1 ? '' : 's'} pending`
          : blockers > 0
            ? `${blockers} planner blocker${blockers === 1 ? '' : 's'}`
            : 'Nothing awaiting review',
      detail:
        input.approvals.length > 0
          ? 'Human authorization is required before execution can continue.'
          : blockers > 0
            ? 'The current plan needs intervention before it can advance.'
            : 'No operator decision is blocking the workflow.',
      tone: input.approvals.length > 0 || blockers > 0 ? 'warning' : 'success',
    },
    {
      key: 'blocked',
      label: 'Blocked',
      value: blocked > 0 ? `${blocked} execution path${blocked === 1 ? '' : 's'} blocked` : 'No blocked paths',
      detail:
        blocked > 0
          ? 'Open each blocked item to inspect the reason code, policy verdict, and evidence.'
          : 'No run is currently denied or awaiting time-locked intervention.',
      tone: blocked > 0 ? 'danger' : 'success',
    },
    {
      key: 'risk',
      label: 'Risk',
      value: `${risk.toUpperCase()} operational exposure`,
      detail:
        risk === 'critical'
          ? 'A destructive or denied action is in play.'
          : risk === 'high'
            ? 'External mutation or approval-gated action requires deliberate review.'
            : risk === 'medium'
              ? 'Observable mutation is underway.'
              : 'Current work is read-heavy or sandbox-local.',
      tone:
        risk === 'critical'
          ? 'danger'
          : risk === 'high'
            ? 'warning'
            : risk === 'medium'
              ? 'info'
              : 'success',
    },
    {
      key: 'evidence',
      label: 'Evidence',
      value: receiptCount > 0 ? `${receiptCount} receipts captured` : 'No receipts sealed yet',
      detail:
        receiptCount > 0
          ? 'Proof and export surfaces can trace the current execution chain.'
          : 'Receipts will appear after runs execute or policy verdicts are issued.',
      tone: receiptCount > 0 ? 'info' : 'neutral',
    },
    {
      key: 'next',
      label: 'Next',
      value:
        input.approvals.length > 0
          ? 'Review pending approvals'
          : input.activePolicy
            ? 'Inspect the current execution queue'
            : 'Draft and activate policy',
      detail:
        input.approvals.length > 0
          ? 'The fastest path forward is clearing the review queue.'
          : input.activePolicy
            ? 'Move from queue health to receipts and proof if the system stays nominal.'
            : 'Governance is not active yet, so execution boundaries are incomplete.',
      tone: input.approvals.length > 0 ? 'warning' : 'info',
    },
  ];
}

export function buildGoalPlan(goal: GoalRecord | null): ExecutionPlan | null {
  if (!goal) {
    return null;
  }

  const steps: ExecutionStep[] = goal.plan_dag.map((task) => ({
    id: task.id,
    title: task.description,
    detail: task.depends_on?.length
      ? `Depends on ${task.depends_on.length} earlier step${task.depends_on.length === 1 ? '' : 's'}.`
      : 'Ready to execute when policy and approvals allow.',
    status: normalizeTaskStatus(task.status),
    dependsOn: task.depends_on,
    artifact: task.receipt_ref
      ? {
          id: task.receipt_ref,
          type: 'receipt',
          title: task.receipt_ref,
          detail: 'Linked proof artifact from the current goal plan.',
        }
      : undefined,
  }));

  return {
    id: goal.id,
    title: goal.status_line || goal.user_prompt,
    summary: goal.user_prompt,
    status:
      goal.blockers && goal.blockers.length > 0
        ? 'blocked'
        : steps.some((step) => step.status === 'running')
          ? 'active'
          : steps.every((step) => step.status === 'done')
            ? 'completed'
            : 'review',
    steps,
  };
}

export function buildDefaultActivity(input: {
  runs: RunRecord[];
  approvals: ApprovalRecord[];
  replays?: ReplayManifest[];
}): ActivityItem[] {
  const runItems = input.runs.slice(0, 3).map<ActivityItem>((run) => ({
    id: run.id,
    title: run.status === 'pending_approval' ? 'Run waiting on approval' : `Run ${run.status}`,
    detail: run.reason_code ?? run.plan_hash ?? 'Governed run updated.',
    timestamp: run.completed_at ?? run.started_at ?? run.created_at,
    tone:
      run.status === 'deny'
        ? 'danger'
        : run.status === 'pending_approval'
          ? 'warning'
          : run.status === 'completed'
            ? 'success'
            : 'info',
  }));

  const approvalItems = input.approvals.slice(0, 2).map<ActivityItem>((approval) => ({
    id: approval.id,
    title: approval.action_summary,
    detail: approval.risk_summary,
    timestamp: approval.created_at,
    tone: approval.status === 'pending' ? 'warning' : 'success',
  }));

  const replayItems = (input.replays ?? []).slice(0, 2).map<ActivityItem>((replay) => ({
    id: replay.id,
    title: replay.status === 'ready' ? 'Replay available' : 'Replay manifest updated',
    detail: replay.evidence_pack_hash,
    timestamp: replay.created_at,
    tone: replay.status === 'ready' ? 'info' : 'neutral',
  }));

  return [...approvalItems, ...runItems, ...replayItems].sort((left, right) =>
    (right.timestamp ?? '').localeCompare(left.timestamp ?? ''),
  );
}

export function buildArtifactsForSurface(input: {
  workspaceId: string;
  runs: RunRecord[];
  approvals: ApprovalRecord[];
  graphs: ToolSurfaceGraph[];
  activePolicy: PolicyVersion | null;
  goal: GoalRecord | null;
}): ArtifactRef[] {
  const artifacts: ArtifactRef[] = [];

  const graph = input.graphs[0];
  if (graph) {
    artifacts.push({
      id: graph.id,
      type: 'graph',
      title: graph.source_uri || graph.source_type,
      detail: `${graph.node_count} nodes imported into the governed topology.`,
      truth: {
        stage: 'active',
        label: 'Canonical topology loaded',
        detail: graph.contract_hash,
      },
    });
  }

  for (const approval of input.approvals.slice(0, 2)) {
    artifacts.push({
      id: approval.id,
      type: 'approval',
      title: approval.action_summary,
      detail: approval.risk_summary,
      truth: deriveApprovalTruth(approval),
    });
  }

  for (const run of input.runs.slice(0, 2)) {
    artifacts.push({
      id: run.id,
      type: 'run',
      title: run.template_id || run.id,
      detail: run.reason_code ?? run.status,
      truth: deriveRunTruth(run),
    });
  }

  if (input.activePolicy) {
    artifacts.push({
      id: input.activePolicy.id,
      type: 'policy',
      title: `Policy v${input.activePolicy.version}`,
      detail: input.activePolicy.compiled_bundle_hash,
      truth: {
        stage: input.activePolicy.status === 'active' ? 'active' : 'draft',
        label: input.activePolicy.status === 'active' ? 'Active policy' : input.activePolicy.status,
        detail: 'Runtime verdicts are derived from this compiled bundle.',
      },
    });
  }

  if (input.goal) {
    artifacts.push({
      id: input.goal.id,
      type: 'goal',
      title: input.goal.status_line,
      detail: input.goal.user_prompt,
      truth: {
        stage: input.goal.blockers?.length ? 'blocked' : 'running',
        label: input.goal.phase,
        detail: `${input.goal.plan_dag.length} planned step${input.goal.plan_dag.length === 1 ? '' : 's'}.`,
      },
    });
  }

  return artifacts.map((artifact) => ({
    ...artifact,
    href: getArtifactHref(input.workspaceId, artifact),
  }));
}

export function formatDateTime(value?: string): string {
  if (!value) {
    return 'Unavailable';
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}

export function formatRelativeTime(value?: string): string {
  if (!value) {
    return 'No timestamp';
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  const deltaMs = date.getTime() - Date.now();
  const minutes = Math.round(deltaMs / 60_000);
  if (Math.abs(minutes) < 60) {
    return new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(minutes, 'minute');
  }

  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) {
    return new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(hours, 'hour');
  }

  const days = Math.round(hours / 24);
  return new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(days, 'day');
}

function maxRisk(left: RiskLevel, right: RiskLevel): RiskLevel {
  const order: RiskLevel[] = ['low', 'medium', 'high', 'critical'];
  return order.indexOf(left) > order.indexOf(right) ? left : right;
}

function normalizeTaskStatus(status: string): ExecutionStep['status'] {
  switch (status.toLowerCase()) {
    case 'running':
    case 'in_progress':
      return 'running';
    case 'done':
    case 'complete':
    case 'completed':
      return 'done';
    case 'blocked':
    case 'waiting':
      return 'blocked';
    case 'failed':
    case 'error':
      return 'failed';
    default:
      return 'pending';
  }
}
