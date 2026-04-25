import '@xyflow/react/dist/style.css';

import { useEffect, useMemo, useState } from 'react';
import dagre from '@dagrejs/dagre';
import { Background, Controls, MiniMap, ReactFlow, type Edge, type Node } from '@xyflow/react';
import { Link } from 'react-router-dom';
import { MessageSquareMore, Pause, Play, RotateCcw, X } from 'lucide-react';
import type { PolicyDraft, PolicyVersion, ToolSurfaceGraph } from '../api/types';
import type { ActivityItem, ArtifactRef, InspectorTab } from '../types/operator';
import { buildGoalPlan, deriveApprovalTruth, deriveRiskLevel, deriveRunTruth, formatDateTime, formatRelativeTime } from './model';
import {
  ActionButton,
  ArtifactList,
  ConfirmActionButton,
  DetailList,
  EmptyState,
  ErrorState,
  JsonPreview,
  LoadingState,
  Panel,
  QueueTable,
  RiskPill,
  SurfaceIntro,
  TopStatusPill,
  TruthBadge,
} from './components';
import {
  useActiveGoal,
  useActivatePolicy,
  useActivePolicy,
  useAdvanceGoal,
  useApproveGoalBlocker,
  useApprovals,
  useCancelTask,
  useCompilePolicy,
  useCreateTask,
  useDraftPolicy,
  useGenerateExport,
  useGraphs,
  useImportToolSurface,
  usePauseTask,
  useReplays,
  useResolveApproval,
  useResumeTask,
  useRun,
  useRunReceipts,
  useRuns,
  useSendChat,
  useSession,
  useSimulations,
  useSubmitRun,
  useSubmitSimulation,
  useTasks,
  useVerifyReceipt,
} from './hooks';
import { useOperatorShell } from './layout';

export function CanvasSurfacePage() {
  const shell = useOperatorShell();
  const graphsQuery = useGraphs(shell.workspaceId);
  const approvalsQuery = useApprovals(shell.workspaceId);
  const importMutation = useImportToolSurface(shell.workspaceId);
  const [selectedGraphIdState, setSelectedGraphId] = useState<string | null>(null);
  const [selectedNodeIdState, setSelectedNodeId] = useState<string | null>(null);
  const [sourceType, setSourceType] = useState('catalog');
  const [sourceUri, setSourceUri] = useState('helm://catalog/demo');
  const [manifestText, setManifestText] = useState('[{"id":"ops","label":"Ops Command","kind":"team"},{"id":"vendor","label":"Vendor Gateway","kind":"service"}]');
  const [importError, setImportError] = useState<string | null>(null);

  const graphs = useMemo(() => graphsQuery.data ?? [], [graphsQuery.data]);
  const selectedGraphId = selectedGraphIdState ?? graphs[0]?.id ?? '';
  const selectedGraph = graphs.find((graph) => graph.id === selectedGraphId) ?? graphs[0];
  const flow = useMemo(() => toFlowGraph(selectedGraph), [selectedGraph]);
  const selectedNodeId = selectedNodeIdState ?? flow.nodes[0]?.id ?? '';
  const selectedNode = useMemo(
    () => flow.nodeRecords.get(selectedNodeId) ?? flow.nodeRecords.values().next().value ?? null,
    [flow.nodeRecords, selectedNodeId],
  );

  useEffect(() => {
    const activity: ActivityItem[] = [
      ...graphs.slice(0, 3).map((graph) => ({
        id: graph.id,
        title: `${graph.node_count} nodes imported`,
        detail: graph.source_uri || graph.source_type,
        timestamp: graph.created_at,
        tone: 'info' as const,
      })),
      ...(approvalsQuery.data ?? []).slice(0, 2).map((approval) => ({
        id: approval.id,
        title: 'Approval linked to topology',
        detail: approval.action_summary,
        timestamp: approval.created_at,
        tone: 'warning' as const,
      })),
    ];

    const overview = selectedNode
      ? (
          <DetailList
            items={[
              { label: 'Node id', value: String(selectedNode.id ?? 'Unavailable') },
              { label: 'Type', value: String(selectedNode.kind ?? selectedNode.type ?? 'Unknown') },
              { label: 'Label', value: String(selectedNode.label ?? selectedNode.name ?? 'Unnamed node') },
              { label: 'Graph', value: selectedGraph?.id ?? 'Unavailable' },
            ]}
          />
        )
      : <p className="operator-empty-inline">Select a node to inspect its properties.</p>;

    const evidence = selectedGraph
      ? (
          <DetailList
            items={[
              { label: 'Schema hash', value: selectedGraph.schema_hash },
              { label: 'Contract hash', value: selectedGraph.contract_hash },
              { label: 'Source', value: selectedGraph.source_uri || selectedGraph.source_type },
              { label: 'Created', value: formatDateTime(selectedGraph.created_at) },
            ]}
          />
        )
      : <p className="operator-empty-inline">No graph selected.</p>;

    const tabs: InspectorTab[] = [
      { id: 'overview', label: 'Overview', content: overview },
      {
        id: 'policy',
        label: 'Policy',
        content: (
          <DetailList
            items={[
              { label: 'Pending approvals', value: String((approvalsQuery.data ?? []).length) },
              { label: 'Topology node count', value: String(selectedGraph?.node_count ?? 0) },
              { label: 'Guardrail', value: 'Topology imports remain inspectable before policy activation.' },
            ]}
          />
        ),
      },
      { id: 'evidence', label: 'Evidence', content: evidence },
      { id: 'history', label: 'History', content: <QueueTable columns={[{ key: 'when', label: 'When' }, { key: 'detail', label: 'Detail' }]} rows={activity.map((item) => ({ id: item.id, when: formatRelativeTime(item.timestamp), detail: item.detail }))} /> },
    ];

    shell.setInspector({
      title: selectedNode ? String(selectedNode.label ?? selectedNode.name ?? 'Topology node') : 'Topology graph',
      subtitle: selectedGraph ? `${selectedGraph.node_count} nodes · ${selectedGraph.source_uri || selectedGraph.source_type}` : 'No imported graph',
      tabs,
    });
    shell.setActivity(activity);
    shell.setArtifacts(
      selectedGraph
        ? [
            {
              id: selectedGraph.id,
              type: 'graph',
              title: selectedGraph.source_uri || selectedGraph.source_type,
              detail: `${selectedGraph.node_count} nodes in the canonical topology.`,
              truth: {
                stage: 'active',
                label: 'Imported topology',
                detail: selectedGraph.contract_hash,
              },
            },
          ]
        : [],
    );

    return () => {
      shell.setInspector(null);
      shell.setActivity(null);
      shell.setArtifacts(null);
    };
  }, [approvalsQuery.data, selectedGraph, selectedNode, graphs, shell]);

  if (graphsQuery.isLoading) {
    return <LoadingState label="Loading topology graph…" />;
  }

  if (graphsQuery.isError) {
    return <ErrorState error={graphsQuery.error} title="Topology graph unavailable" retry={() => void graphsQuery.refetch()} />;
  }

  return (
    <div className="operator-surface-page">
      <SurfaceIntro
        eyebrow="Canvas"
        title="Canonical topology and work graph"
        description="Topology is first-class here: what exists, what is selected, what approvals touch it, and what proof exists for each change."
      />

      <div className="operator-page-grid canvas-layout">
        <Panel
          title="Topology workspace"
          description={
            selectedGraph
              ? `${selectedGraph.node_count} nodes loaded from ${selectedGraph.source_uri || selectedGraph.source_type}.`
              : 'No tool-surface graph is available yet.'
          }
          className="operator-panel-primary"
        >
          {selectedGraph ? (
            <div className="operator-flow-shell">
              <ReactFlow
                edges={flow.edges}
                fitView
                nodes={flow.nodes}
                nodesDraggable={false}
                onNodeClick={(_, node) => setSelectedNodeId(node.id)}
                panOnDrag
                proOptions={{ hideAttribution: true }}
              >
                <Background gap={24} />
                <Controls showInteractive={false} />
                <MiniMap />
              </ReactFlow>
            </div>
          ) : (
            <EmptyState
              title="No imported topology"
              body="Canvas only renders real tool-surface graphs. Import a manifest or connect a supported source to establish canonical structure."
            />
          )}
        </Panel>

        <Panel
          title="Topology sources"
          description="Import a real graph manifest or switch between existing graph records."
        >
          {graphs.length > 0 ? (
            <div className="operator-stack">
              {graphs.map((graph) => (
                <button
                  key={graph.id}
                  className={`operator-select-row${graph.id === selectedGraph?.id ? ' is-active' : ''}`}
                  onClick={() => setSelectedGraphId(graph.id)}
                  type="button"
                >
                  <div>
                    <strong>{graph.source_uri || graph.source_type}</strong>
                    <p>{graph.node_count} nodes · {formatRelativeTime(graph.created_at)}</p>
                  </div>
                  <TopStatusPill label="Hash" tone="neutral" value={graph.contract_hash.slice(0, 10)} />
                </button>
              ))}
            </div>
          ) : null}

          <form
            className="operator-form"
            onSubmit={(event) => {
              event.preventDefault();
              try {
                const parsed = JSON.parse(manifestText) as unknown;
                const manifest = Array.isArray(parsed)
                  ? parsed.filter(isRecord)
                  : isRecord(parsed)
                    ? [parsed]
                    : [];
                if (manifest.length === 0) {
                  throw new Error('Manifest must be an object or array of objects.');
                }
                setImportError(null);
                importMutation.mutate({
                  sourceType,
                  sourceUri,
                  manifest,
                });
              } catch (error) {
                setImportError(error instanceof Error ? error.message : 'Manifest must be valid JSON.');
              }
            }}
          >
            <label>
              <span>Source type</span>
              <input onChange={(event) => setSourceType(event.target.value)} value={sourceType} />
            </label>
            <label>
              <span>Source uri</span>
              <input onChange={(event) => setSourceUri(event.target.value)} value={sourceUri} />
            </label>
            <label>
              <span>Manifest JSON</span>
              <textarea onChange={(event) => setManifestText(event.target.value)} rows={8} value={manifestText} />
            </label>
            <div className="operator-form-actions">
              <button className="operator-button primary" disabled={importMutation.isPending} type="submit">
                Import topology
              </button>
            </div>
            {importError ? <ErrorState error={new Error(importError)} title="Manifest error" /> : null}
            {importMutation.error ? <ErrorState error={importMutation.error} title="Import failed" /> : null}
          </form>
        </Panel>
      </div>
    </div>
  );
}

export function OperateSurfacePage() {
  const shell = useOperatorShell();
  const sessionQuery = useSession();
  const runsQuery = useRuns(shell.workspaceId);
  const approvalsQuery = useApprovals(shell.workspaceId);
  const simulationsQuery = useSimulations(shell.workspaceId);
  const goalQuery = useActiveGoal();
  const submitRun = useSubmitRun(shell.workspaceId);
  const resolveApproval = useResolveApproval(shell.workspaceId);
  const tasksQuery = useTasks(shell.workspaceId);
  const createTask = useCreateTask(shell.workspaceId);
  const pauseTask = usePauseTask(shell.workspaceId);
  const resumeTask = useResumeTask(shell.workspaceId);
  const cancelTask = useCancelTask(shell.workspaceId);
  const [templateId, setTemplateId] = useState('ops.health-check');
  const [taskLabel, setTaskLabel] = useState('Scheduled health check');
  const [taskCron, setTaskCron] = useState('@every 1h');
  const [planText, setPlanText] = useState(
    JSON.stringify(
      {
        actions: [
          {
            tool_id: 'shell:echo',
            method: 'exec',
            effect_class: 'E1',
          },
        ],
      },
      null,
      2,
    ),
  );
  const [planError, setPlanError] = useState<string | null>(null);
  const [selectedRunIdState, setSelectedRunId] = useState<string | null>(null);

  const runs = useMemo(() => runsQuery.data ?? [], [runsQuery.data]);
  const approvals = useMemo(() => approvalsQuery.data ?? [], [approvalsQuery.data]);
  const simulations = useMemo(() => simulationsQuery.data ?? [], [simulationsQuery.data]);
  const tasks = useMemo(() => tasksQuery.data ?? [], [tasksQuery.data]);
  const selectedRunId = selectedRunIdState ?? runs[0]?.id ?? '';
  const selectedRun = runs.find((run) => run.id === selectedRunId) ?? runs[0];
  const selectedApproval = approvals[0];

  useEffect(() => {
    const tabs: InspectorTab[] = selectedApproval
      ? [
          {
            id: 'overview',
            label: 'Overview',
            content: (
              <DetailList
                items={[
                  { label: 'Action', value: selectedApproval.action_summary },
                  { label: 'Risk', value: selectedApproval.risk_summary },
                  { label: 'Effect class', value: selectedApproval.effect_class },
                  { label: 'Time lock', value: `${selectedApproval.timelock_seconds}s` },
                ]}
              />
            ),
          },
          {
            id: 'execution',
            label: 'Execution',
            content: <TruthBadge truth={deriveApprovalTruth(selectedApproval)} />,
          },
          {
            id: 'policy',
            label: 'Policy',
            content: (
              <DetailList
                items={[
                  { label: 'Policy hash', value: selectedApproval.policy_hash || 'Unavailable' },
                  { label: 'Approval level', value: selectedApproval.approval_level },
                  { label: 'Status', value: selectedApproval.status },
                ]}
              />
            ),
          },
          {
            id: 'history',
            label: 'History',
            content: (
              <DetailList
                items={[
                  { label: 'Created', value: formatDateTime(selectedApproval.created_at) },
                  { label: 'Expires', value: formatDateTime(selectedApproval.expires_at) },
                  { label: 'Resolved', value: formatDateTime(selectedApproval.resolved_at) },
                ]}
              />
            ),
          },
        ]
      : selectedRun
        ? [
            {
              id: 'overview',
              label: 'Overview',
              content: (
                <DetailList
                  items={[
                    { label: 'Run id', value: selectedRun.id },
                    { label: 'Verdict', value: selectedRun.verdict ?? 'Pending' },
                    { label: 'Status', value: selectedRun.status },
                    { label: 'Reason', value: selectedRun.reason_code ?? 'Awaiting result' },
                  ]}
                />
              ),
            },
            {
              id: 'execution',
              label: 'Execution',
              content: <TruthBadge truth={deriveRunTruth(selectedRun)} />,
            },
            {
              id: 'policy',
              label: 'Policy',
              content: (
                <DetailList
                  items={[
                    { label: 'Policy hash', value: selectedRun.policy_hash || 'Unavailable' },
                    { label: 'Plan hash', value: selectedRun.plan_hash || 'Unavailable' },
                    { label: 'Effect class', value: selectedRun.effect_class ?? 'Not declared' },
                  ]}
                />
              ),
            },
            {
              id: 'history',
              label: 'History',
              content: (
                <DetailList
                  items={[
                    { label: 'Created', value: formatDateTime(selectedRun.created_at) },
                    { label: 'Started', value: formatDateTime(selectedRun.started_at) },
                    { label: 'Completed', value: formatDateTime(selectedRun.completed_at) },
                  ]}
                />
              ),
            },
          ]
        : [{ id: 'overview', label: 'Overview', content: <p className="operator-empty-inline">Select a run or approval.</p> }];

    const activity: ActivityItem[] = [
      ...approvals.slice(0, 3).map((approval) => ({
        id: approval.id,
        title: approval.action_summary,
        detail: approval.risk_summary,
        timestamp: approval.created_at,
        tone: 'warning' as const,
      })),
      ...runs.slice(0, 3).map((run) => ({
        id: run.id,
        title: run.template_id || 'Governed run',
        detail: run.reason_code ?? run.status,
        timestamp: run.completed_at ?? run.started_at ?? run.created_at,
        tone:
          run.status === 'completed'
            ? ('success' as const)
            : run.status === 'pending_approval'
              ? ('warning' as const)
              : ('info' as const),
      })),
    ];

    shell.setInspector({
      title: selectedApproval ? 'Approval review' : selectedRun ? 'Run detail' : 'Execution queue',
      subtitle: selectedApproval?.id ?? selectedRun?.id ?? 'Live governed execution',
      tabs,
    });
    shell.setActivity(activity);
    shell.setArtifacts([
      ...approvals.slice(0, 2).map<ArtifactRef>((approval) => ({
        id: approval.id,
        type: 'approval',
        title: approval.action_summary,
        detail: approval.risk_summary,
        truth: deriveApprovalTruth(approval),
      })),
      ...runs.slice(0, 2).map<ArtifactRef>((run) => ({
        id: run.id,
        type: 'run',
        title: run.template_id || run.id,
        detail: run.reason_code ?? run.status,
        truth: deriveRunTruth(run),
      })),
    ]);

    return () => {
      shell.setInspector(null);
      shell.setActivity(null);
      shell.setArtifacts(null);
    };
  }, [approvals, runs, selectedApproval, selectedRun, shell]);

  if (runsQuery.isLoading || approvalsQuery.isLoading || simulationsQuery.isLoading) {
    return <LoadingState label="Loading governed execution surfaces…" />;
  }

  if (runsQuery.isError) {
    return <ErrorState error={runsQuery.error} title="Run stream unavailable" retry={() => void runsQuery.refetch()} />;
  }

  return (
    <div className="operator-surface-page">
      <SurfaceIntro
        eyebrow="Operate"
        title="Governed execution board"
        description="Runs, approvals, and operational posture are visible together so the operator can move from queue health to action confidence in one pass."
      />

      <div className="operator-page-grid operate-layout">
        <Panel
          title="Execution queue"
          description="Launch governed work or inspect the current stream."
          className="operator-panel-primary"
        >
          <QueueTable
            columns={[
              { key: 'run', label: 'Run' },
              { key: 'status', label: 'Status' },
              { key: 'risk', label: 'Risk' },
              { key: 'updated', label: 'Updated' },
            ]}
            rows={runs.map((run) => ({
              id: run.id,
              run: (
                <button className="operator-inline-button" onClick={() => setSelectedRunId(run.id)} type="button">
                  {run.template_id || run.id}
                </button>
              ),
              status: run.status,
              risk: <RiskPill risk={deriveRiskLevel({ effectClass: run.effect_class, status: run.status })} />,
              updated: formatRelativeTime(run.completed_at ?? run.started_at ?? run.created_at),
            }))}
          />

          <form
            className="operator-form"
            onSubmit={(event) => {
              event.preventDefault();
              try {
                const parsed = JSON.parse(planText) as Record<string, unknown>;
                setPlanError(null);
                submitRun.mutate({ templateId, plan: parsed });
              } catch (error) {
                setPlanError(error instanceof Error ? error.message : 'Plan must be valid JSON.');
              }
            }}
          >
            <label>
              <span>Template id</span>
              <input onChange={(event) => setTemplateId(event.target.value)} value={templateId} />
            </label>
            <label>
              <span>Plan JSON</span>
              <textarea onChange={(event) => setPlanText(event.target.value)} rows={8} value={planText} />
            </label>
            <div className="operator-form-actions">
              <button className="operator-button primary" disabled={submitRun.isPending} type="submit">
                <Play size={16} />
                Submit governed run
              </button>
            </div>
            {planError ? <ErrorState error={new Error(planError)} title="Plan error" /> : null}
            {submitRun.error ? <ErrorState error={submitRun.error} title="Run submission failed" /> : null}
          </form>
        </Panel>

        <Panel title="Needs review" description="Approval state is explicit: risk, consequence, hold, and next action.">
          {approvals.length > 0 ? (
            <div className="operator-stack">
              {approvals.map((approval) => (
                <article key={approval.id} className="operator-review-card">
                  <div>
                    <strong>{approval.action_summary}</strong>
                    <p>{approval.risk_summary}</p>
                    <div className="operator-inline-meta">
                      <RiskPill risk={deriveRiskLevel({ effectClass: approval.effect_class, pendingApprovals: approvals.length })} />
                      <span>{approval.effect_class}</span>
                      <span>{approval.timelock_seconds}s timelock</span>
                    </div>
                  </div>
                  <div className="operator-review-actions">
                    <button
                      className="operator-button secondary"
                      onClick={() =>
                        resolveApproval.mutate({
                          approvalId: approval.id,
                          approverId: sessionQuery.data?.principal_id ?? 'local-operator',
                          decision: 'APPROVE',
                          reason: 'Approved from HELM Operate.',
                        })
                      }
                      type="button"
                    >
                      Approve
                    </button>
                    <ConfirmActionButton
                      confirmLabel="Confirm deny"
                      description="Denying this request will keep execution blocked and write the decision into the approval record."
                      label="Deny"
                      onConfirm={() =>
                        resolveApproval.mutate({
                          approvalId: approval.id,
                          approverId: sessionQuery.data?.principal_id ?? 'local-operator',
                          decision: 'DENY',
                          reason: 'Denied from HELM Operate.',
                        })
                      }
                    />
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <EmptyState title="No approvals pending" body="The review queue is currently clear." compact />
          )}
        </Panel>

        <Panel title="System posture" description="Async work stays visible beyond the current thread.">
          <div className="operator-stack">
            <TopStatusPill
              label="Goal phase"
              tone="info"
              value={goalQuery.data?.phase ?? 'No active goal'}
            />
            <TopStatusPill
              label="Simulations"
              tone={simulations.length > 0 ? 'info' : 'neutral'}
              value={String(simulations.length)}
            />
            <TopStatusPill
              label="Exceptions"
              tone={approvals.length > 0 ? 'warning' : 'success'}
              value={String(approvals.length)}
            />
            {goalQuery.data ? (
              <DetailList
                items={[
                  { label: 'Status line', value: goalQuery.data.status_line },
                  { label: 'Planned steps', value: String(goalQuery.data.plan_dag.length) },
                  { label: 'Blockers', value: String(goalQuery.data.blockers?.length ?? 0) },
                ]}
              />
            ) : null}
            {selectedRun ? <TruthBadge truth={deriveRunTruth(selectedRun)} /> : null}
          </div>
        </Panel>
        <Panel title="Scheduled tasks" description="Async work with governed lifecycle.">
          <div className="operator-stack">
            {tasks.length > 0 ? (
              <QueueTable
                columns={[
                  { key: 'label', label: 'Task' },
                  { key: 'schedule', label: 'Schedule' },
                  { key: 'status', label: 'Status' },
                  { key: 'runs', label: 'Runs' },
                  { key: 'actions', label: '' },
                ]}
                rows={tasks.map((task) => ({
                  id: task.id,
                  label: task.label || task.template_id,
                  schedule: task.cron_expr || 'One-shot',
                  status: task.status,
                  runs: String(task.run_count),
                  actions: (
                    <div className="operator-inline-actions">
                      {task.status === 'pending' && (
                        <button
                          className="operator-icon-button"
                          onClick={() => pauseTask.mutate(task.id)}
                          title="Pause task"
                          type="button"
                        >
                          <Pause size={14} />
                        </button>
                      )}
                      {task.status === 'paused' && (
                        <button
                          className="operator-icon-button"
                          onClick={() => resumeTask.mutate(task.id)}
                          title="Resume task"
                          type="button"
                        >
                          <RotateCcw size={14} />
                        </button>
                      )}
                      {(task.status === 'pending' || task.status === 'paused' || task.status === 'running') && (
                        <button
                          className="operator-icon-button danger"
                          onClick={() => cancelTask.mutate(task.id)}
                          title="Cancel task"
                          type="button"
                        >
                          <X size={14} />
                        </button>
                      )}
                    </div>
                  ),
                }))}
              />
            ) : (
              <EmptyState title="No scheduled tasks" body="Create a task to automate governed work on a schedule." compact />
            )}

            <form
              className="operator-form"
              onSubmit={(event) => {
                event.preventDefault();
                createTask.mutate({
                  label: taskLabel,
                  templateId,
                  cronExpr: taskCron,
                });
              }}
            >
              <label>
                <span>Task label</span>
                <input onChange={(event) => setTaskLabel(event.target.value)} value={taskLabel} />
              </label>
              <label>
                <span>Schedule (cron)</span>
                <input onChange={(event) => setTaskCron(event.target.value)} value={taskCron} placeholder="@every 1h, @daily, or @every 30m" />
              </label>
              <div className="operator-form-actions">
                <button className="operator-button secondary" disabled={createTask.isPending} type="submit">
                  <Play size={16} />
                  Schedule task
                </button>
              </div>
              {createTask.error ? <ErrorState error={createTask.error} title="Task creation failed" /> : null}
            </form>
          </div>
        </Panel>
      </div>
    </div>
  );
}

export function GovernSurfacePage() {
  const shell = useOperatorShell();
  const graphsQuery = useGraphs(shell.workspaceId);
  const activePolicyQuery = useActivePolicy(shell.workspaceId);
  const simulationsQuery = useSimulations(shell.workspaceId);
  const draftPolicy = useDraftPolicy(shell.workspaceId);
  const compilePolicy = useCompilePolicy(shell.workspaceId);
  const activatePolicy = useActivatePolicy(shell.workspaceId);
  const submitSimulation = useSubmitSimulation(shell.workspaceId);
  const [objective, setObjective] = useState('Allow low-risk operational checks while requiring approval for all external mutations.');
  const [constraintsText, setConstraintsText] = useState('require_approval_e3\ndeny_e4');
  const [draft, setDraft] = useState<PolicyDraft | null>(null);
  const [compiledVersion, setCompiledVersion] = useState<PolicyVersion | null>(null);
  const graphs = graphsQuery.data ?? [];
  const activePolicy = activePolicyQuery.data ?? null;
  const simulations = useMemo(() => simulationsQuery.data ?? [], [simulationsQuery.data]);
  const selectedGraph = graphs[0];

  useEffect(() => {
    const candidate = compiledVersion ?? activePolicy;
    shell.setInspector({
      title: candidate ? `Policy version ${candidate.version}` : 'Policy workbench',
      subtitle: candidate?.compiled_bundle_hash ?? 'Draft, compile, simulate, and activate policy from one workbench.',
      tabs: [
        {
          id: 'overview',
          label: 'Overview',
          content: (
            <DetailList
              items={[
                { label: 'Active policy', value: activePolicy ? `v${activePolicy.version}` : 'None active' },
                { label: 'Draft ready', value: draft ? draft.id : 'No draft in session' },
                { label: 'Selected graph', value: selectedGraph?.id ?? 'No graph imported' },
              ]}
            />
          ),
        },
        {
          id: 'policy',
          label: 'Policy',
          content: candidate ? <JsonPreview data={candidate.compiled_bundle} label="Compiled bundle" /> : <p className="operator-empty-inline">Compile a draft to inspect the bundle.</p>,
        },
        {
          id: 'execution',
          label: 'Execution',
          content: (
            <DetailList
              items={[
                { label: 'Blast radius', value: `${selectedGraph?.node_count ?? 0} topology nodes inherit the next verdict set.` },
                { label: 'Approval requirement', value: constraintsText.includes('require_approval_e3') ? 'E3 actions remain approval gated.' : 'No explicit E3 constraint.' },
                { label: 'Rollout consequence', value: 'Activation changes future run verdicts immediately.' },
              ]}
            />
          ),
        },
        {
          id: 'history',
          label: 'History',
          content: (
            <QueueTable
              columns={[
                { key: 'simulation', label: 'Simulation' },
                { key: 'status', label: 'Status' },
                { key: 'scope', label: 'Scope' },
              ]}
              rows={simulations.map((simulation) => ({
                id: simulation.id,
                simulation: simulation.template_id,
                status: simulation.status,
                scope: simulation.scope,
              }))}
            />
          ),
        },
      ],
    });
    shell.setActivity(
      simulations.slice(0, 4).map((simulation) => ({
        id: simulation.id,
        title: simulation.template_id,
        detail: simulation.actual_verdict ?? simulation.status,
        timestamp: simulation.completed_at ?? simulation.created_at,
        tone: simulation.actual_verdict === 'DENY' ? 'warning' : 'info',
      })),
    );
    shell.setArtifacts(
      activePolicy
        ? [
            {
              id: activePolicy.id,
              type: 'policy',
              title: `Policy v${activePolicy.version}`,
              detail: activePolicy.compiled_bundle_hash,
              truth: {
                stage: activePolicy.status === 'active' ? 'active' : 'draft',
                label: activePolicy.status,
                detail: 'Runtime verdicts derive from this bundle.',
              },
            },
          ]
        : [],
    );

    return () => {
      shell.setInspector(null);
      shell.setActivity(null);
      shell.setArtifacts(null);
    };
  }, [activePolicy, compiledVersion, constraintsText, draft, selectedGraph, shell, simulations]);

  if (graphsQuery.isLoading || activePolicyQuery.isLoading || simulationsQuery.isLoading) {
    return <LoadingState label="Loading policy workbench…" />;
  }

  return (
    <div className="operator-surface-page">
      <SurfaceIntro
        eyebrow="Govern"
        title="Policy workbench"
        description="Draft, compile, simulate, and activate policy with blast radius, approval requirements, and rollout consequence visible together."
      />

      <div className="operator-page-grid govern-layout">
        <Panel title="Active policy" description="Canonical runtime policy currently enforcing execution.">
          {activePolicy ? (
            <div className="operator-stack">
              <TruthBadge
                truth={{
                  stage: 'active',
                  label: `Policy v${activePolicy.version} active`,
                  detail: activePolicy.compiled_bundle_hash,
                }}
              />
              <DetailList
                items={[
                  { label: 'Activated', value: formatDateTime(activePolicy.activated_at) },
                  { label: 'Created', value: formatDateTime(activePolicy.created_at) },
                  { label: 'Workspace', value: activePolicy.workspace_id },
                ]}
              />
            </div>
          ) : (
            <EmptyState
              title="No active policy"
              body="Draft and activate a policy before approving or executing higher-impact work."
              compact
            />
          )}
        </Panel>

        <Panel
          title="Draft and compile"
          description="Create a real draft against the imported topology, then compile before activation."
          className="operator-panel-primary"
        >
          {selectedGraph ? (
            <form
              className="operator-form"
              onSubmit={(event) => {
                event.preventDefault();
                draftPolicy.mutate(
                  {
                    toolSurfaceId: selectedGraph.id,
                    objective,
                    constraints: constraintsText
                      .split('\n')
                      .map((line) => line.trim())
                      .filter(Boolean),
                  },
                  {
                    onSuccess: (result) => setDraft(result),
                  },
                );
              }}
            >
              <label>
                <span>Objective</span>
                <textarea onChange={(event) => setObjective(event.target.value)} rows={4} value={objective} />
              </label>
              <label>
                <span>Constraints</span>
                <textarea onChange={(event) => setConstraintsText(event.target.value)} rows={4} value={constraintsText} />
              </label>
              <div className="operator-form-actions">
                <button className="operator-button primary" disabled={draftPolicy.isPending} type="submit">
                  Draft policy
                </button>
                <button
                  className="operator-button secondary"
                  disabled={!draft || compilePolicy.isPending}
                  onClick={() => {
                    if (!draft) {
                      return;
                    }
                    compilePolicy.mutate(draft.id, {
                      onSuccess: (result) => setCompiledVersion(result),
                    });
                  }}
                  type="button"
                >
                  Compile draft
                </button>
                <ConfirmActionButton
                  confirmLabel="Activate policy"
                  description="Activating this compiled policy changes future runtime verdicts for the entire workspace."
                  disabled={!compiledVersion || activatePolicy.isPending}
                  label="Activate"
                  onConfirm={() => {
                    if (!compiledVersion) {
                      return;
                    }
                    activatePolicy.mutate(compiledVersion.id);
                  }}
                  tone="warning"
                />
              </div>
              {draftPolicy.error ? <ErrorState error={draftPolicy.error} title="Draft failed" /> : null}
              {compilePolicy.error ? <ErrorState error={compilePolicy.error} title="Compile failed" /> : null}
              {activatePolicy.error ? <ErrorState error={activatePolicy.error} title="Activation failed" /> : null}
            </form>
          ) : (
            <EmptyState
              title="No topology available"
              body="Import a tool-surface graph in Canvas before drafting policy."
            />
          )}
        </Panel>

        <Panel title="Blast radius and simulation" description="Understand consequence before activation.">
          <div className="operator-stack">
            <TopStatusPill label="Topology nodes" tone="info" value={String(selectedGraph?.node_count ?? 0)} />
            <TopStatusPill
              label="Approval path"
              tone={constraintsText.includes('require_approval_e3') ? 'warning' : 'neutral'}
              value={constraintsText.includes('require_approval_e3') ? 'E3 gated' : 'No explicit E3 gate'}
            />
            <TopStatusPill label="Current simulations" tone="neutral" value={String(simulations.length)} />
            <button
              className="operator-button secondary"
              disabled={submitSimulation.isPending}
              onClick={() =>
                submitSimulation.mutate({
                  templateId: compiledVersion?.id ?? activePolicy?.id ?? 'policy-check',
                  scope: selectedGraph ? `graph:${selectedGraph.id}` : 'workspace',
                })
              }
              type="button"
            >
              Run policy simulation
            </button>
            {submitSimulation.error ? <ErrorState error={submitSimulation.error} title="Simulation failed" /> : null}
          </div>
        </Panel>
      </div>
    </div>
  );
}

export function ProofSurfacePage() {
  const shell = useOperatorShell();
  const runsQuery = useRuns(shell.workspaceId);
  const replaysQuery = useReplays(shell.workspaceId);
  const exportMutation = useGenerateExport(shell.workspaceId);
  const verifyReceipt = useVerifyReceipt();
  const [selectedRunIdState, setSelectedRunId] = useState<string | null>(null);
  const [selectedReceiptHashState, setSelectedReceiptHash] = useState<string | null>(null);
  const runs = useMemo(() => runsQuery.data ?? [], [runsQuery.data]);
  const defaultRunWithReceipts = runs.find((run) => (run.receipts?.length ?? 0) > 0) ?? runs[0];
  const selectedRunId = selectedRunIdState ?? defaultRunWithReceipts?.id ?? '';
  const selectedRun = runs.find((run) => run.id === selectedRunId) ?? defaultRunWithReceipts;
  const runQuery = useRun(shell.workspaceId, selectedRun?.id ?? '');
  const receiptsQuery = useRunReceipts(shell.workspaceId, selectedRun?.id ?? '');
  const receipts = useMemo(
    () => receiptsQuery.data ?? runQuery.data?.receipts ?? [],
    [receiptsQuery.data, runQuery.data?.receipts],
  );
  const selectedReceiptHash = selectedReceiptHashState ?? receipts[0]?.receipt_hash ?? '';
  const selectedReceipt = receipts.find((receipt) => receipt.receipt_hash === selectedReceiptHash) ?? receipts[0];
  const replays = useMemo(() => replaysQuery.data ?? [], [replaysQuery.data]);

  useEffect(() => {
    shell.setInspector({
      title: selectedReceipt ? selectedReceipt.receipt_type : 'Proof surface',
      subtitle: selectedReceipt?.receipt_hash ?? 'Receipts, replay, and export stay together here.',
      tabs: [
        {
          id: 'overview',
          label: 'Overview',
          content: selectedReceipt ? (
            <DetailList
              items={[
                { label: 'Receipt type', value: selectedReceipt.receipt_type },
                { label: 'Verdict', value: selectedReceipt.verdict ?? 'Not declared' },
                { label: 'Reason', value: selectedReceipt.reason_code ?? 'Unavailable' },
                { label: 'Timestamp', value: formatDateTime(selectedReceipt.timestamp) },
              ]}
            />
          ) : (
            <p className="operator-empty-inline">Select a receipt to inspect it.</p>
          ),
        },
        {
          id: 'evidence',
          label: 'Evidence',
          content: selectedRun ? (
            <DetailList
              items={[
                { label: 'Evidence pack hash', value: selectedRun.evidence_pack_hash ?? 'Unavailable' },
                { label: 'Replay manifest', value: selectedRun.replay_manifest_id ?? 'Unavailable' },
                { label: 'Run id', value: selectedRun.id },
              ]}
            />
          ) : (
            <p className="operator-empty-inline">No run selected.</p>
          ),
        },
        {
          id: 'history',
          label: 'History',
          content: (
            <QueueTable
              columns={[
                { key: 'lamport', label: 'Lamport' },
                { key: 'type', label: 'Type' },
                { key: 'time', label: 'Timestamp' },
              ]}
              rows={receipts.map((receipt) => ({
                id: receipt.receipt_hash,
                lamport: String(receipt.lamport_clock),
                type: receipt.receipt_type,
                time: formatDateTime(receipt.timestamp),
              }))}
            />
          ),
        },
      ],
    });
    shell.setActivity(
      receipts.slice(0, 4).map((receipt) => ({
        id: receipt.receipt_hash,
        title: receipt.receipt_type,
        detail: receipt.reason_code ?? receipt.verdict ?? 'Receipt captured.',
        timestamp: receipt.timestamp,
        tone: receipt.verdict === 'DENY' ? 'warning' : 'info',
      })),
    );
    shell.setArtifacts([
      ...receipts.slice(0, 2).map<ArtifactRef>((receipt) => ({
        id: receipt.receipt_hash,
        type: 'receipt',
        title: receipt.receipt_type,
        detail: receipt.reason_code ?? receipt.verdict ?? receipt.signature,
        truth: {
          stage: receipt.verdict === 'DENY' ? 'blocked' : 'verified',
          label: receipt.verdict ?? 'Receipt sealed',
          detail: receipt.signature.slice(0, 18),
        },
      })),
      ...replays.slice(0, 1).map<ArtifactRef>((replay) => ({
        id: replay.id,
        type: 'evidence',
        title: replay.id,
        detail: replay.evidence_pack_hash,
        truth: {
          stage: replay.public_safe ? 'verified' : 'unverified',
          label: replay.status,
          detail: replay.proofgraph_root || 'No proof graph root published',
        },
      })),
    ]);
    return () => {
      shell.setInspector(null);
      shell.setActivity(null);
      shell.setArtifacts(null);
    };
  }, [receipts, replays, selectedReceipt, selectedRun, shell]);

  if (runsQuery.isLoading || replaysQuery.isLoading) {
    return <LoadingState label="Loading receipt and replay state…" />;
  }

  return (
    <div className="operator-surface-page">
      <SurfaceIntro
        eyebrow="Proof"
        title="Receipts, replay, and export"
        description="Trust is native here: inspect the receipt chain, replay availability, evidence pointers, and export bundles without leaving the workspace."
      />

      <div className="operator-page-grid proof-layout">
        <Panel title="Receipt chain" description="Canonical receipts for the selected run." className="operator-panel-primary">
          {runs.length > 0 ? (
            <div className="operator-stack">
              <div className="operator-segment-list">
                {runs.map((run) => (
                  <button
                    key={run.id}
                    className={`operator-segment${run.id === selectedRun?.id ? ' is-active' : ''}`}
                    onClick={() => setSelectedRunId(run.id)}
                    type="button"
                  >
                    {run.template_id || run.id}
                  </button>
                ))}
              </div>
              <div className="operator-stack">
                {receipts.map((receipt) => (
                  <button
                    key={receipt.receipt_hash}
                    className={`operator-select-row${receipt.receipt_hash === selectedReceipt?.receipt_hash ? ' is-active' : ''}`}
                    onClick={() => setSelectedReceiptHash(receipt.receipt_hash)}
                    type="button"
                  >
                    <div>
                      <strong>{receipt.receipt_type}</strong>
                      <p>{receipt.reason_code ?? receipt.verdict ?? receipt.signature.slice(0, 22)}</p>
                    </div>
                    <TopStatusPill label="Lamport" tone="neutral" value={String(receipt.lamport_clock)} />
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <EmptyState title="No runs with receipts" body="Execute governed work before a receipt chain can be inspected." />
          )}
        </Panel>

        <Panel title="Verification" description="Validate the selected receipt against the verifier endpoint.">
          {selectedReceipt ? (
            <div className="operator-stack">
              <TruthBadge
                truth={{
                  stage: verifyReceipt.data?.receipt?.signatureValid ? 'verified' : 'approved',
                  label: verifyReceipt.data?.receipt?.signatureValid ? 'Verification passed' : 'Verification pending',
                  detail: selectedReceipt.receipt_hash,
                }}
              />
              <button
                className="operator-button primary"
                disabled={verifyReceipt.isPending}
                onClick={() => verifyReceipt.mutate(selectedReceipt)}
                type="button"
              >
                Verify receipt
              </button>
              {verifyReceipt.error ? <ErrorState error={verifyReceipt.error} title="Verification failed" /> : null}
              {verifyReceipt.data?.receipt ? <JsonPreview data={verifyReceipt.data.receipt} label="Verifier response" /> : null}
            </div>
          ) : (
            <EmptyState title="Select a receipt" body="Verification requires a concrete receipt from the current chain." compact />
          )}
        </Panel>

        <Panel title="Evidence and export" description="Replay manifests and export bundles remain adjacent to the receipt chain.">
          <div className="operator-stack">
            <button
              className="operator-button secondary"
              disabled={exportMutation.isPending}
              onClick={() => exportMutation.mutate()}
              type="button"
            >
              Generate export bundle
            </button>
            {exportMutation.data ? (
              <DetailList
                items={[
                  { label: 'Export id', value: exportMutation.data.id },
                  { label: 'Manifest hash', value: exportMutation.data.manifest_hash },
                  { label: 'Status', value: exportMutation.data.status },
                ]}
              />
            ) : null}
            {replays.length > 0 ? (
              <div className="operator-stack">
                {replays.map((replay) => (
                  <article key={replay.id} className="operator-review-card">
                    <div>
                      <strong>{replay.id}</strong>
                      <p>{replay.evidence_pack_hash}</p>
                    </div>
                    <TopStatusPill label="Replay" tone="info" value={replay.status} />
                  </article>
                ))}
              </div>
            ) : (
              <EmptyState title="No replay manifests" body="Replay stays empty until a run publishes public-safe proof metadata." compact />
            )}
          </div>
        </Panel>
      </div>
    </div>
  );
}

export function ChatSurfacePage() {
  const shell = useOperatorShell();
  const sendChat = useSendChat();
  const goalQuery = useActiveGoal();
  const advanceGoal = useAdvanceGoal();
  const approveGoalBlocker = useApproveGoalBlocker();
  const [conversationId] = useState(() => createConversationId());
  const [draft, setDraft] = useState('Review the current queue, identify blocked execution, and propose the safest next step.');
  const [messages, setMessages] = useState<Array<{ id: string; role: 'user' | 'assistant'; content: string; timestamp: string }>>([]);
  const plan = buildGoalPlan(goalQuery.data ?? null);

  useEffect(() => {
    const artifacts: ArtifactRef[] = [
      ...(plan?.steps ?? [])
        .filter((step) => step.artifact)
        .map((step) => ({
          id: step.artifact!.id,
          type: step.artifact!.type,
          title: step.artifact!.title,
          detail: step.artifact!.detail,
        })),
    ];

    shell.setInspector({
      title: plan?.title ?? 'Conversation context',
      subtitle: plan?.summary ?? 'Chat is an entry point into governed objects, not the whole product.',
      tabs: [
        {
          id: 'overview',
          label: 'Overview',
          content: (
            <DetailList
              items={[
                { label: 'Conversation', value: conversationId },
                { label: 'Messages', value: String(messages.length) },
                { label: 'Goal phase', value: goalQuery.data?.phase ?? 'No active goal' },
              ]}
            />
          ),
        },
        {
          id: 'execution',
          label: 'Execution',
          content: plan ? (
            <QueueTable
              columns={[
                { key: 'step', label: 'Step' },
                { key: 'status', label: 'Status' },
                { key: 'detail', label: 'Detail' },
              ]}
              rows={plan.steps.map((step) => ({
                id: step.id,
                step: step.title,
                status: step.status,
                detail: step.detail,
              }))}
            />
          ) : (
            <EmptyState title="No plan available" body="Send a message to ask HELM to propose or continue governed work." compact />
          ),
        },
        {
          id: 'policy',
          label: 'Policy',
          content: (
            <DetailList
              items={[
                { label: 'Blockers', value: String(goalQuery.data?.blockers?.length ?? 0) },
                { label: 'Status line', value: goalQuery.data?.status_line ?? 'No active goal' },
                { label: 'Outcomes', value: String(goalQuery.data?.outcomes?.length ?? 0) },
              ]}
            />
          ),
        },
        {
          id: 'evidence',
          label: 'Evidence',
          content: <ArtifactList artifacts={artifacts} workspaceId={shell.workspaceId} />,
        },
      ],
    });
    shell.setActivity(
      messages.slice(-4).map((message) => ({
        id: message.id,
        title: message.role === 'assistant' ? 'Assistant update' : 'Operator input',
        detail: message.content,
        timestamp: message.timestamp,
        tone: message.role === 'assistant' ? 'info' : 'neutral',
      })),
    );
    shell.setArtifacts(artifacts);
    return () => {
      shell.setInspector(null);
      shell.setActivity(null);
      shell.setArtifacts(null);
    };
  }, [conversationId, goalQuery.data, messages, plan, shell]);

  return (
    <div className="operator-surface-page">
      <SurfaceIntro
        eyebrow="Chat"
        title="Conversation with governed handoff"
        description="Plans, blockers, approvals, and artifacts stay visible beside the thread so work does not disappear into prose."
      />

      <div className="operator-page-grid chat-layout">
        <Panel title="Conversation" description="Use chat to propose, reroute, and clarify work.">
          <div className="operator-chat-thread">
            {messages.length > 0 ? (
              messages.map((message) => (
                <article key={message.id} className={`operator-chat-message role-${message.role}`}>
                  <header>
                    <strong>{message.role === 'assistant' ? 'HELM' : 'Operator'}</strong>
                    <time dateTime={message.timestamp}>{formatRelativeTime(message.timestamp)}</time>
                  </header>
                  <p>{message.content}</p>
                </article>
              ))
            ) : (
              <EmptyState
                title="No conversation yet"
                body="Start with an operational question or ask for a governed plan."
                compact
              />
            )}
          </div>
          <form
            className="operator-form"
            onSubmit={(event) => {
              event.preventDefault();
              const nextUserMessage = {
                id: `${conversationId}-user-${Date.now()}`,
                role: 'user' as const,
                content: draft,
                timestamp: new Date().toISOString(),
              };
              const history = [...messages, nextUserMessage].map((message) => ({
                role: message.role,
                content: message.content,
              }));

              setMessages((current) => [...current, nextUserMessage]);
              setDraft('');

              sendChat.mutate(
                {
                  message: nextUserMessage.content,
                  conversationId,
                  history,
                },
                {
                  onSuccess: (response) => {
                    setMessages((current) => [
                      ...current,
                      {
                        id: response.id,
                        role: 'assistant',
                        content: response.content,
                        timestamp: response.timestamp,
                      },
                    ]);
                    void goalQuery.refetch();
                  },
                },
              );
            }}
          >
            <label>
              <span>Message</span>
              <textarea onChange={(event) => setDraft(event.target.value)} rows={4} value={draft} />
            </label>
            <div className="operator-form-actions">
              <button className="operator-button primary" disabled={sendChat.isPending || draft.trim().length === 0} type="submit">
                <MessageSquareMore size={16} />
                Send to HELM
              </button>
            </div>
            {sendChat.error ? <ErrorState error={sendChat.error} title="Chat request failed" /> : null}
          </form>
        </Panel>

        <Panel
          title="Live execution plan"
          description="Proposal, approval, execution, and proof remain structurally separate."
        >
          {plan ? (
            <div className="operator-stack">
              <TruthBadge
                truth={{
                  stage: plan.status === 'blocked' ? 'blocked' : plan.status === 'active' ? 'running' : 'proposed',
                  label: plan.title,
                  detail: plan.summary,
                }}
              />
              <QueueTable
                columns={[
                  { key: 'step', label: 'Step' },
                  { key: 'status', label: 'Status' },
                  { key: 'depends', label: 'Depends on' },
                ]}
                rows={plan.steps.map((step) => ({
                  id: step.id,
                  step: step.title,
                  status: step.status,
                  depends: step.dependsOn?.join(', ') || 'None',
                }))}
              />
              <div className="operator-form-actions">
                <button
                  className="operator-button secondary"
                  disabled={advanceGoal.isPending}
                  onClick={() => advanceGoal.mutate(goalQuery.data!.id)}
                  type="button"
                >
                  Continue plan
                </button>
                {goalQuery.data?.blockers?.[0] ? (
                  <ActionButton
                    action={{
                      id: goalQuery.data.blockers[0].id,
                      title: 'Approve first blocker',
                      detail: goalQuery.data.blockers[0].detail,
                      emphasis: 'primary',
                    }}
                    onClick={() =>
                      approveGoalBlocker.mutate({
                        goalId: goalQuery.data!.id,
                        blockerId: goalQuery.data!.blockers![0].id,
                      })
                    }
                  />
                ) : null}
              </div>
            </div>
          ) : (
            <EmptyState
              title="No active plan"
              body="Chat becomes materially more useful once a governed goal is present."
            />
          )}
        </Panel>

        <Panel title="Linked artifacts" description="Chat outputs stay connected to canonical objects.">
          <div className="operator-stack">
            <TopStatusPill label="Goal phase" tone="info" value={goalQuery.data?.phase ?? 'No active goal'} />
            <TopStatusPill label="Blockers" tone={goalQuery.data?.blockers?.length ? 'warning' : 'success'} value={String(goalQuery.data?.blockers?.length ?? 0)} />
            <TopStatusPill label="Outcomes" tone="neutral" value={String(goalQuery.data?.outcomes?.length ?? 0)} />
            <ArtifactList
              artifacts={
                (plan?.steps ?? [])
                  .filter((step) => step.artifact)
                  .map((step) => step.artifact!)
              }
              workspaceId={shell.workspaceId}
            />
            <Link className="operator-inline-link" to={`/workspaces/${shell.workspaceId}/operate`}>
              Open execution board
            </Link>
          </div>
        </Panel>
      </div>
    </div>
  );
}

function createConversationId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID();
  }
  return `conversation-${Date.now()}`;
}

function toFlowGraph(graph?: ToolSurfaceGraph): {
  nodes: Node[];
  edges: Edge[];
  nodeRecords: Map<string, Record<string, unknown>>;
} {
  if (!graph) {
    return { nodes: [], edges: [], nodeRecords: new Map() };
  }

  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setGraph({ rankdir: 'LR', nodesep: 32, ranksep: 64 });
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  const nodeRecords = new Map<string, Record<string, unknown>>();
  const nodes: Node[] = graph.nodes.map((record, index) => {
    const id = String(record.id ?? record.name ?? record.label ?? `node-${index + 1}`);
    const label = String(record.label ?? record.name ?? record.id ?? `Node ${index + 1}`);
    const kind = String(record.kind ?? record.type ?? 'component');
    nodeRecords.set(id, record);
    dagreGraph.setNode(id, { width: 220, height: 84 });
    return {
      id,
      data: { label: `${label}\n${kind}` },
      draggable: false,
      position: { x: 0, y: 0 },
      style: {
        background: 'var(--operator-bg-panel)',
        border: '1px solid var(--operator-line)',
        borderRadius: 14,
        color: 'var(--operator-text)',
        fontSize: 13,
        padding: 12,
        whiteSpace: 'pre-line',
        width: 220,
      },
    };
  });

  const edges: Edge[] = (graph.edges ?? []).map((record, index) => {
    const source = String(record.source ?? record.from ?? nodes[0]?.id ?? `source-${index}`);
    const target = String(record.target ?? record.to ?? nodes[nodes.length - 1]?.id ?? `target-${index}`);
    dagreGraph.setEdge(source, target);
    return {
      id: String(record.id ?? `edge-${index + 1}`),
      source,
      target,
      animated: false,
      style: { stroke: 'var(--operator-accent)', strokeWidth: 1.5, opacity: 0.5 },
    };
  });

  dagre.layout(dagreGraph);

  for (const node of nodes) {
    const position = dagreGraph.node(node.id);
    node.position = {
      x: position.x - 110,
      y: position.y - 42,
    };
  }

  return { nodes, edges, nodeRecords };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
