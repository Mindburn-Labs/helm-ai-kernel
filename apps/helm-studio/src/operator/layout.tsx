/* eslint-disable react-refresh/only-export-components */
import { useMemo, useState } from 'react';
import { Link, Outlet, useLocation, useOutletContext, useParams } from 'react-router-dom';
import { Bell, Command, LayoutPanelTop, List, PanelRightOpen, ShieldCheck } from 'lucide-react';
import type { InspectorTab, ActivityItem, ArtifactRef } from '../types/operator';
import type { Surface } from '../types/domain';
import { SurfaceNavigation, TopStatusPill, SignalStrip, Inspector, ArtifactList, DetailList, ActivityFeed } from './components';
import { useActiveGoal, useActivePolicy, useApprovals, useGraphs, useReplays, useRuns, useSession, useWorkspace } from './hooks';
import {
  buildArtifactsForSurface,
  buildControlStrip,
  buildDefaultActivity,
  formatDateTime,
  getSurfaceLabel,
} from './model';

interface InspectorState {
  title: string;
  subtitle?: string;
  tabs: InspectorTab[];
}

export interface OperatorShellContextValue {
  workspaceId: string;
  surface: Surface;
  setInspector: (inspector: InspectorState | null) => void;
  setActivity: (activity: ActivityItem[] | null) => void;
  setArtifacts: (artifacts: ArtifactRef[] | null) => void;
}

export function useOperatorShell() {
  return useOutletContext<OperatorShellContextValue>();
}

export function OperatorLayout() {
  const { workspaceId = '' } = useParams();
  const location = useLocation();
  const surface = parseSurface(location.pathname);
  const [surfaceInspector, setSurfaceInspector] = useState<InspectorState | null>(null);
  const [surfaceActivity, setSurfaceActivity] = useState<ActivityItem[] | null>(null);
  const [surfaceArtifacts, setSurfaceArtifacts] = useState<ArtifactRef[] | null>(null);
  const [inspectorVisible, setInspectorVisible] = useState(true);
  const [activityVisible, setActivityVisible] = useState(true);

  const sessionQuery = useSession();
  const workspaceQuery = useWorkspace(workspaceId);
  const runsQuery = useRuns(workspaceId);
  const approvalsQuery = useApprovals(workspaceId);
  const graphsQuery = useGraphs(workspaceId);
  const policyQuery = useActivePolicy(workspaceId);
  const goalQuery = useActiveGoal();
  const replaysQuery = useReplays(workspaceId);

  const runs = useMemo(() => runsQuery.data ?? [], [runsQuery.data]);
  const approvals = useMemo(() => approvalsQuery.data ?? [], [approvalsQuery.data]);
  const graphs = useMemo(() => graphsQuery.data ?? [], [graphsQuery.data]);
  const activePolicy = policyQuery.data ?? null;
  const goal = goalQuery.data ?? null;
  const replays = useMemo(() => replaysQuery.data ?? [], [replaysQuery.data]);

  const signals = useMemo(
    () =>
      buildControlStrip({
        runs,
        approvals,
        goal,
        activePolicy,
      }),
    [activePolicy, approvals, goal, runs],
  );

  const defaultArtifacts = useMemo(
    () =>
      buildArtifactsForSurface({
        workspaceId,
        runs,
        approvals,
        graphs,
        activePolicy,
        goal,
      }),
    [activePolicy, approvals, goal, graphs, runs, workspaceId],
  );

  const defaultActivity = useMemo(
    () =>
      buildDefaultActivity({
        runs,
        approvals,
        replays,
      }),
    [approvals, replays, runs],
  );

  const defaultInspector = useMemo<InspectorState>(() => {
    const workspace = workspaceQuery.data;
    const session = sessionQuery.data;

    return {
      title: workspace?.name ?? 'Workspace unavailable',
      subtitle:
        workspace?.id ??
        'The workspace record could not be loaded. Operator surfaces will show live errors instead of mock data.',
      tabs: [
        {
          id: 'overview',
          label: 'Overview',
          content: (
            <DetailList
              items={[
                { label: 'Surface', value: getSurfaceLabel(surface) },
                { label: 'Workspace', value: workspace?.id ?? 'Unavailable' },
                { label: 'Profile', value: workspace?.profile ?? 'Not declared' },
                { label: 'Runtime status', value: workspace?.status ?? 'Unknown' },
                { label: 'Session', value: session?.principal_id ?? 'Anonymous' },
              ]}
            />
          ),
        },
        {
          id: 'execution',
          label: 'Execution',
          content: (
            <DetailList
              items={[
                { label: 'Active runs', value: String(runs.filter((run) => run.status === 'running').length) },
                { label: 'Pending approvals', value: String(approvals.length) },
                { label: 'Goal blockers', value: String(goal?.blockers?.length ?? 0) },
                { label: 'Last activity', value: defaultActivity[0]?.timestamp ? formatDateTime(defaultActivity[0].timestamp) : 'No recent events' },
              ]}
            />
          ),
        },
        {
          id: 'policy',
          label: 'Policy',
          content: (
            <DetailList
              items={[
                { label: 'Active policy', value: activePolicy ? `Version ${activePolicy.version}` : 'None active' },
                { label: 'Compiled hash', value: activePolicy?.compiled_bundle_hash ?? 'Unavailable' },
                { label: 'Policy status', value: activePolicy?.status ?? 'No active policy' },
              ]}
            />
          ),
        },
        {
          id: 'evidence',
          label: 'Evidence',
          content: <ArtifactList workspaceId={workspaceId} artifacts={surfaceArtifacts ?? defaultArtifacts} />,
        },
        {
          id: 'history',
          label: 'History',
          content: <ActivityFeed items={surfaceActivity ?? defaultActivity} />,
        },
      ],
    };
  }, [
    activePolicy,
    approvals.length,
    defaultActivity,
    defaultArtifacts,
    goal?.blockers?.length,
    runs,
    sessionQuery.data,
    surface,
    surfaceActivity,
    surfaceArtifacts,
    workspaceId,
    workspaceQuery.data,
  ]);

  const inspector = surfaceInspector ?? defaultInspector;
  const activity = surfaceActivity ?? defaultActivity;
  const outletContext = useMemo<OperatorShellContextValue>(
    () => ({
      workspaceId,
      surface,
      setInspector: setSurfaceInspector,
      setActivity: setSurfaceActivity,
      setArtifacts: setSurfaceArtifacts,
    }),
    [surface, workspaceId],
  );

  return (
    <div className="operator-shell">
      <aside className="operator-rail">
        <div className="operator-brand-lockup">
          <span className="operator-brand-mark">HELM</span>
          <p>Governed execution for real operators.</p>
        </div>

        <div className="operator-workspace-card">
          <span className="operator-eyebrow">Workspace</span>
          <strong>{workspaceQuery.data?.name ?? 'Loading workspace'}</strong>
          <p>{workspaceQuery.data?.id ?? workspaceId}</p>
        </div>

        <SurfaceNavigation
          activeSurface={surface}
          approvalCount={approvals.length}
          workspaceId={workspaceId}
        />

        <div className="operator-rail-section">
          <span className="operator-eyebrow">Shortcuts</span>
          <Link className="operator-rail-link" to="/workspaces/new">
            Create workspace
          </Link>
          <Link className="operator-rail-link" to="/public/verify">
            Public verify
          </Link>
        </div>

        <div className="operator-rail-status">
          <TopStatusPill
            label="Authority"
            tone={sessionQuery.data ? 'success' : 'neutral'}
            value={sessionQuery.data?.principal_id ?? 'Local operator'}
          />
          <TopStatusPill
            label="Runtime"
            tone={workspaceQuery.data?.status === 'active' ? 'success' : 'warning'}
            value={workspaceQuery.data?.status ?? 'Unknown'}
          />
        </div>
      </aside>

      <div className="operator-main">
        <header className="operator-topbar">
          <div>
            <span className="operator-eyebrow">Workspace / {getSurfaceLabel(surface)}</span>
            <h1>{workspaceQuery.data?.name ?? 'Operator workspace'}</h1>
          </div>

          <div className="operator-topbar-actions">
            <TopStatusPill
              label="Profile"
              tone="info"
              value={workspaceQuery.data?.profile ?? 'Not set'}
            />
            <TopStatusPill
              label="Policy"
              tone={activePolicy ? 'success' : 'warning'}
              value={activePolicy ? `v${activePolicy.version} active` : 'Not active'}
            />
            <TopStatusPill
              label="Alerts"
              tone={approvals.length > 0 ? 'warning' : 'neutral'}
              value={String(approvals.length)}
            />
            <button
              className="operator-icon-button"
              onClick={() => setInspectorVisible((value) => !value)}
              title="Toggle inspector"
              type="button"
            >
              <PanelRightOpen size={16} />
            </button>
            <button
              className="operator-icon-button"
              onClick={() => setActivityVisible((value) => !value)}
              title="Toggle activity"
              type="button"
            >
              <List size={16} />
            </button>
            <Link className="operator-icon-button" title="Open chat" to={`/workspaces/${workspaceId}/chat`}>
              <Command size={16} />
            </Link>
            <button className="operator-icon-button" title="Notifications" type="button">
              <Bell size={16} />
            </button>
          </div>
        </header>

        <SignalStrip signals={signals} />

        <div className="operator-content-grid">
          <main className="operator-surface-shell" id="main-content">
            <Outlet context={outletContext} />
          </main>

          {inspectorVisible ? (
            <Inspector
              subtitle={inspector.subtitle}
              tabs={inspector.tabs}
              title={inspector.title}
            />
          ) : null}
        </div>

        {activityVisible ? (
          <section className="operator-activity-rail" aria-label="Runtime activity" tabIndex={0}>
            <header className="operator-activity-header">
              <div>
                <span className="operator-eyebrow">Runtime activity</span>
                <h2>Recent state changes</h2>
              </div>
              <div className="operator-activity-chrome">
                <LayoutPanelTop size={16} />
                <ShieldCheck size={16} />
              </div>
            </header>
            <ActivityFeed items={activity} />
          </section>
        ) : null}
      </div>
    </div>
  );
}

function parseSurface(pathname: string): Surface {
  const segment = pathname.split('/').filter(Boolean)[2];
  switch (segment) {
    case 'operate':
    case 'research':
    case 'govern':
    case 'proof':
    case 'chat':
      return segment;
    default:
      return 'canvas';
  }
}
