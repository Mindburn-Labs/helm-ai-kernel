import { describe, expect, it } from 'vitest';
import { buildArtifactsForSurface, buildControlStrip, buildGoalPlan, deriveApprovalTruth, deriveRunTruth } from './model';
import type { GoalRecord, PolicyVersion, RunRecord } from '../api/types';

const NOW = '2026-03-29T10:00:00Z';

describe('operator model', () => {
  it('builds the control strip in the required operator order', () => {
    const signals = buildControlStrip({
      runs: [
        {
          id: 'run_live',
          workspace_id: 'workspace_acme',
          plan_hash: 'sha256:plan-live',
          policy_hash: 'sha256:policy-live',
          status: 'running',
          effect_class: 'E2',
          created_at: NOW,
        },
        {
          id: 'run_blocked',
          workspace_id: 'workspace_acme',
          plan_hash: 'sha256:plan-blocked',
          policy_hash: 'sha256:policy-live',
          status: 'pending_approval',
          effect_class: 'E3',
          created_at: NOW,
        },
      ] satisfies RunRecord[],
      approvals: [
        {
          id: 'approval_demo',
          run_id: 'run_blocked',
          workspace_id: 'workspace_acme',
          intent_hash: 'sha256:intent',
          summary_hash: 'sha256:summary',
          policy_hash: 'sha256:policy-live',
          effect_class: 'E3',
          action_summary: 'Approve vendor gateway change',
          risk_summary: 'External mutation requires review.',
          approval_level: 'operator',
          status: 'pending',
          min_hold_seconds: 60,
          timelock_seconds: 300,
          created_at: NOW,
          expires_at: NOW,
        },
      ],
      goal: {
        id: 'goal_demo',
        user_prompt: 'Review the blocked change.',
        phase: 'review',
        outcomes: [],
        plan_dag: [],
        blockers: [{ id: 'blocker_1', kind: 'approval', detail: 'Needs operator review.' }],
        created_at: NOW,
        updated_at: NOW,
        status_line: 'Blocked vendor release needs review',
      },
      activePolicy: {
        id: 'policy_active',
        workspace_id: 'workspace_acme',
        version: 3,
        compiled_bundle_hash: 'sha256:bundle',
        compiled_bundle: {},
        status: 'active',
        created_at: NOW,
      },
    });

    expect(signals.map((signal) => signal.label)).toEqual([
      'Now',
      'Needs You',
      'Blocked',
      'Risk',
      'Evidence',
      'Next',
    ]);
    expect(signals[0]?.value).toContain('governed runs active');
    expect(signals[1]?.value).toContain('approval');
    expect(signals[2]?.tone).toBe('danger');
    expect(signals[3]?.value).toContain('HIGH');
  });

  it('derives governed truth states for approvals and runs', () => {
    expect(
      deriveApprovalTruth({
        id: 'approval_demo',
        run_id: 'run_demo',
        workspace_id: 'workspace_acme',
        intent_hash: 'sha256:intent',
        summary_hash: 'sha256:summary',
        policy_hash: 'sha256:policy',
        effect_class: 'E3',
        action_summary: 'Approve deployment',
        risk_summary: 'External mutation requires approval.',
        approval_level: 'operator',
        status: 'pending',
        min_hold_seconds: 30,
        timelock_seconds: 300,
        created_at: NOW,
        expires_at: NOW,
      }).stage,
    ).toBe('proposed');

    expect(
      deriveRunTruth({
        id: 'run_complete',
        workspace_id: 'workspace_acme',
        plan_hash: 'sha256:plan',
        policy_hash: 'sha256:policy',
        status: 'completed',
        verdict: 'ALLOW',
        created_at: NOW,
      }).stage,
    ).toBe('verified');
  });

  it('links artifacts back to their primary operator surfaces', () => {
    const activePolicy: PolicyVersion = {
      id: 'policy_active',
      workspace_id: 'workspace_acme',
      version: 4,
      compiled_bundle_hash: 'sha256:bundle',
      compiled_bundle: {},
      status: 'active',
      created_at: NOW,
    };

    const artifacts = buildArtifactsForSurface({
      workspaceId: 'workspace_acme',
      runs: [
        {
          id: 'run_demo',
          workspace_id: 'workspace_acme',
          template_id: 'vendor.deploy',
          plan_hash: 'sha256:plan',
          policy_hash: 'sha256:policy',
          status: 'running',
          created_at: NOW,
        },
      ],
      approvals: [],
      graphs: [
        {
          id: 'graph_demo',
          workspace_id: 'workspace_acme',
          source_type: 'catalog',
          source_uri: 'helm://catalog/acme',
          schema_hash: 'sha256:schema',
          contract_hash: 'sha256:contract',
          node_count: 2,
          nodes: [],
          edges: [],
          created_at: NOW,
        },
      ],
      activePolicy,
      goal: null,
    });

    expect(artifacts.map((artifact) => artifact.href)).toEqual([
      '/workspaces/workspace_acme/canvas',
      '/workspaces/workspace_acme/operate',
      '/workspaces/workspace_acme/govern',
    ]);
  });

  it('builds an execution plan that preserves dependencies and receipt refs', () => {
    const goal: GoalRecord = {
      id: 'goal_demo',
      user_prompt: 'Resolve the blocked rollout.',
      phase: 'review',
      outcomes: ['Receipt published'],
      plan_dag: [
        {
          id: 'step_plan',
          description: 'Inspect the current run stream',
          status: 'completed',
        },
        {
          id: 'step_proof',
          description: 'Open the latest receipt',
          status: 'running',
          depends_on: ['step_plan'],
          receipt_ref: 'rcpt_demo',
        },
      ],
      blockers: [],
      created_at: NOW,
      updated_at: NOW,
      status_line: 'Receipt review in progress',
    };

    const plan = buildGoalPlan(goal);

    expect(plan?.status).toBe('active');
    expect(plan?.steps[1]?.dependsOn).toEqual(['step_plan']);
    expect(plan?.steps[1]?.artifact?.id).toBe('rcpt_demo');
  });
});
