import { useState, type ReactNode } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { ArrowRight, Plus } from 'lucide-react';
import { ErrorState, LoadingState, Panel, SurfaceIntro, TopStatusPill } from './components';
import { useCreateWorkspace, useOperatorWorkspaces, useSession } from './hooks';

export function WorkspaceListPage() {
  const workspacesQuery = useOperatorWorkspaces();

  if (workspacesQuery.isLoading) {
    return <LoadingState label="Loading workspaces…" />;
  }

  if (workspacesQuery.isError) {
    return (
      <div className="operator-standalone-page">
        <ErrorState
          error={workspacesQuery.error}
          retry={() => {
            void workspacesQuery.refetch();
          }}
          title="Workspace index unavailable"
        />
      </div>
    );
  }

  return (
    <div className="operator-standalone-page">
      <SurfaceIntro
        actions={
          <Link className="operator-button primary" to="/workspaces/new">
            <Plus size={16} />
            Create workspace
          </Link>
        }
        description="Choose a governed workspace or create a new one. Control, policy, proof, and execution all begin from a real workspace record."
        eyebrow="Operator index"
        title="Workspace control plane"
      />

      <div className="operator-page-grid two-up">
        {(workspacesQuery.data ?? []).map((workspace) => (
          <Panel
            key={workspace.id}
            actions={
              workspace.source === 'controlplane' ? (
                <TopStatusPill label="Source" tone="warning" value="Controlplane only" />
              ) : (
                <Link className="operator-inline-link" to={`/workspaces/${workspace.id}/canvas`}>
                  Open canvas
                  <ArrowRight size={14} />
                </Link>
              )
            }
            description={workspace.id}
            title={workspace.name}
          >
            <div className="operator-metric-row">
              <TopStatusPill label="Profile" tone="info" value={workspace.profile ?? 'Not set'} />
              <TopStatusPill label="Mode" tone="neutral" value={workspace.mode ?? 'internal'} />
              <TopStatusPill label="Status" tone="success" value={workspace.status ?? 'active'} />
            </div>
            <p className="operator-panel-copy">
              {workspace.source === 'controlplane'
                ? 'This workspace exists in the organization directory, but no Studio workspace record is available yet. Provision it before opening operator surfaces.'
                : 'Open the operator canvas to inspect governed topology, approvals, policy, and proof.'}
            </p>
          </Panel>
        ))}
      </div>

      {(workspacesQuery.data ?? []).length === 0 ? (
        <Panel
          title="No Studio workspaces yet"
          description="The operator shell only opens real workspace records."
          actions={
            <Link className="operator-button primary" to="/workspaces/new">
              Create the first workspace
            </Link>
          }
        >
          <p className="operator-panel-copy">
            Create a workspace to establish a canonical topology, policy boundary, receipt chain,
            and governed execution queue.
          </p>
        </Panel>
      ) : null}
    </div>
  );
}

export function WorkspaceCreatePage() {
  const navigate = useNavigate();
  const sessionQuery = useSession();
  const createWorkspace = useCreateWorkspace();
  const [name, setName] = useState('Northwind Operations');
  const [mode, setMode] = useState('internal');
  const [profile, setProfile] = useState('enterprise_pilot');

  return (
    <div className="operator-standalone-page">
      <SurfaceIntro
        eyebrow="Workspace create"
        title="Create a governed workspace"
        description="Provision a real Studio workspace, then land directly in Canvas with policy and execution context ready."
      >
        <div className="operator-create-grid">
          <Panel
            title="Workspace scope"
            description="Create the canonical record first. Controlplane provisioning runs opportunistically if a tenant session exists."
          >
            <form
              className="operator-form"
              onSubmit={(event) => {
                event.preventDefault();
                createWorkspace.mutate(
                  {
                    name,
                    mode,
                    profile,
                    tenantId: sessionQuery.data?.tenant_id,
                    edition: sessionQuery.data?.edition,
                    offerCode: sessionQuery.data?.offer_code,
                    plan: sessionQuery.data?.edition === 'oss' ? 'free' : 'trial',
                  },
                  {
                    onSuccess: ({ workspace }) => {
                      navigate(`/workspaces/${workspace.id}/canvas`);
                    },
                  },
                );
              }}
            >
              <label>
                <span>Workspace name</span>
                <input onChange={(event) => setName(event.target.value)} value={name} />
              </label>
              <label>
                <span>Studio mode</span>
                <select onChange={(event) => setMode(event.target.value)} value={mode}>
                  <option value="internal">internal</option>
                  <option value="public_demo">public_demo</option>
                  <option value="selfhost_source">selfhost_source</option>
                </select>
              </label>
              <label>
                <span>Operator profile</span>
                <select onChange={(event) => setProfile(event.target.value)} value={profile}>
                  <option value="enterprise_pilot">enterprise_pilot</option>
                  <option value="smb">smb</option>
                  <option value="public_demo">public_demo</option>
                </select>
              </label>
              <div className="operator-form-actions">
                <button className="operator-button primary" disabled={createWorkspace.isPending} type="submit">
                  {createWorkspace.isPending ? 'Creating workspace…' : 'Create workspace'}
                </button>
                <Link className="operator-button ghost" to="/workspaces">
                  Cancel
                </Link>
              </div>
              {createWorkspace.error ? (
                <ErrorState
                  error={createWorkspace.error}
                  title="Workspace creation failed"
                />
              ) : null}
            </form>
          </Panel>

          <Panel
            title="What happens next"
            description="The new workspace opens directly into the operator shell."
          >
            <ol className="operator-ordered-list">
              <li>Canvas loads the real topology graph and shows what exists or what still needs import.</li>
              <li>Operate opens the queue, approvals, and governed runtime state.</li>
              <li>Govern activates policy so approvals, receipts, and risk boundaries stay explicit.</li>
            </ol>
            <div className="operator-metric-row">
              <TopStatusPill
                label="Tenant"
                tone={sessionQuery.data?.tenant_id ? 'success' : 'warning'}
                value={sessionQuery.data?.tenant_id ?? 'No browser session'}
              />
              <TopStatusPill
                label="Edition"
                tone="info"
                value={sessionQuery.data?.edition ?? 'studio only'}
              />
            </div>
          </Panel>
        </div>
      </SurfaceIntro>
    </div>
  );
}

export function LegacyRoutePage({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="operator-standalone-page">
      <Panel title={title} description="Removed from the primary IA">
        <p className="operator-panel-copy">{description}</p>
        <Link className="operator-button primary" to="/workspaces">
          Return to workspaces
        </Link>
      </Panel>
    </div>
  );
}

export function NotFoundPage() {
  return (
    <div className="operator-standalone-page">
      <Panel title="Page not found" description="This route is not part of the current HELM operator shell.">
        <p className="operator-panel-copy">
          Use the workspace index or public verification entry points to return to a supported flow.
        </p>
        <div className="operator-form-actions">
          <Link className="operator-button primary" to="/workspaces">
            Go to workspaces
          </Link>
          <Link className="operator-button ghost" to="/public/verify">
            Public verify
          </Link>
        </div>
      </Panel>
    </div>
  );
}

export function WorkspaceAccessGuard({ children }: { children: ReactNode }) {
  const workspacesQuery = useOperatorWorkspaces();

  if (workspacesQuery.isLoading) {
    return <LoadingState label="Checking workspace access…" />;
  }

  if (workspacesQuery.isError) {
    return (
      <div className="operator-standalone-page">
        <ErrorState
          error={workspacesQuery.error}
          title="Workspace access could not be verified"
        />
      </div>
    );
  }

  if ((workspacesQuery.data ?? []).length === 0) {
    return <Navigate replace to="/workspaces/new" />;
  }

  return <>{children}</>;
}
