import { afterEach, describe, expect, it, vi } from 'vitest';
import { studioApi } from './studio';

describe('studio API adapters', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('reads the active policy from the workspace-scoped endpoint', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          id: 'policy_active',
          workspace_id: 'workspace_acme',
          version: 2,
          compiled_bundle_hash: 'sha256:bundle',
          compiled_bundle: {},
          status: 'active',
          created_at: '2026-03-29T10:00:00Z',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    const result = await studioApi.getActivePolicy('workspace_acme');

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/workspaces/workspace_acme/policy/active',
      expect.objectContaining({
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    expect(result.version).toBe(2);
  });

  it('posts run submissions to the governed run endpoint', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          id: 'run_demo',
          workspace_id: 'workspace_acme',
          template_id: 'ops.health-check',
          plan_hash: 'sha256:plan',
          policy_hash: 'sha256:policy',
          status: 'queued',
          created_at: '2026-03-29T10:00:00Z',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    await studioApi.submitRun({
      workspaceId: 'workspace_acme',
      templateId: 'ops.health-check',
      plan: { actions: [] },
    });

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/workspaces/workspace_acme/runs',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          workspace_id: 'workspace_acme',
          template_id: 'ops.health-check',
          plan: { actions: [] },
        }),
      }),
    );
  });

  it('reads approval detail from the new approval-detail endpoint', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          id: 'approval_demo',
          run_id: 'run_demo',
          workspace_id: 'workspace_acme',
          intent_hash: 'sha256:intent',
          summary_hash: 'sha256:summary',
          policy_hash: 'sha256:policy',
          effect_class: 'E3',
          action_summary: 'Approve vendor gateway release',
          risk_summary: 'External mutation requires review.',
          approval_level: 'operator',
          status: 'pending',
          min_hold_seconds: 60,
          timelock_seconds: 300,
          created_at: '2026-03-29T10:00:00Z',
          expires_at: '2026-03-29T11:00:00Z',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    const approval = await studioApi.getApproval('workspace_acme', 'approval_demo');

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/workspaces/workspace_acme/approvals/approval_demo',
      expect.objectContaining({
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    expect(approval.status).toBe('pending');
  });
});
