package mcp

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGovernanceFirewall_Intercept_Allow(t *testing.T) {
	eval := &mockEvaluator{verdict: guardian.VerdictAllow}
	fw := NewGovernanceFirewall(eval, nil)

	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:  "test-tool",
		SessionID: "sess-1",
	})
	assert.NoError(t, err)
}

func TestGovernanceFirewall_Intercept_Block(t *testing.T) {
	eval := &mockEvaluator{verdict: guardian.VerdictBlock, reason: "policy violation"}
	fw := NewGovernanceFirewall(eval, nil)

	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:  "dangerous-tool",
		SessionID: "sess-2",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "governance blocked execution")
	assert.Contains(t, err.Error(), "policy violation")
}

func TestGovernanceFirewall_Intercept_Intervene(t *testing.T) {
	eval := &mockEvaluator{verdict: guardian.VerdictIntervene, reason: "human approval required"}
	fw := NewGovernanceFirewall(eval, nil)

	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:  "high-risk-tool",
		SessionID: "sess-3",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "governance requires approval")
}

func TestGovernanceFirewall_Intercept_EvaluatorError(t *testing.T) {
	eval := &mockEvaluator{err: assert.AnError}
	fw := NewGovernanceFirewall(eval, nil)

	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName: "any-tool",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "governance check failed")
}

func TestGovernanceFirewall_WrapHandler_Allow(t *testing.T) {
	eval := &mockEvaluator{verdict: guardian.VerdictAllow}
	catalog := NewInMemoryCatalog()
	require.NoError(t, catalog.Register(context.Background(), ToolRef{
		Name: "test", EffectClass: "E0", RiskTier: contracts.RiskTierLow,
	}))
	fw := NewGovernanceFirewall(eval, catalog)

	executed := false
	handler := func(ctx context.Context, req ToolExecutionRequest) (ToolExecutionResponse, error) {
		executed = true
		return ToolExecutionResponse{Content: "success"}, nil
	}

	wrapped := fw.WrapToolHandler(handler)
	resp, err := wrapped(context.Background(), ToolExecutionRequest{ToolName: "test", SessionID: "s1"})
	require.NoError(t, err)

	assert.True(t, executed, "handler should have been executed")
	assert.Equal(t, "success", resp.Content)
	assert.True(t, resp.Evaluated)
	assert.False(t, resp.IsError)
}

func TestGovernanceFirewall_WrapHandler_Block(t *testing.T) {
	eval := &mockEvaluator{verdict: guardian.VerdictBlock, reason: "blocked"}
	fw := NewGovernanceFirewall(eval, nil)

	executed := false
	handler := func(ctx context.Context, req ToolExecutionRequest) (ToolExecutionResponse, error) {
		executed = true
		return ToolExecutionResponse{Content: "success"}, nil
	}

	wrapped := fw.WrapToolHandler(handler)
	resp, err := wrapped(context.Background(), ToolExecutionRequest{ToolName: "test", SessionID: "s2"})
	require.NoError(t, err)

	assert.False(t, executed, "handler should NOT have been executed")
	assert.True(t, resp.IsError)
	assert.Contains(t, resp.Content, "Access Denied")
	assert.True(t, resp.Evaluated)
}

func TestGovernanceFirewall_Intercept_Pending(t *testing.T) {
	eval := &mockEvaluator{verdict: string(contracts.VerdictEscalate), reason: "needs approval"}
	fw := NewGovernanceFirewall(eval, nil)

	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:  "risky-tool",
		SessionID: "sess-4",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "governance requires approval")
}

func TestGovernanceFirewall_Intercept_NonCanonicalVerdictFailsClosed(t *testing.T) {
	eval := &mockEvaluator{verdict: "ALLOW_WITH_WARNINGS", reason: "adapter drift"}
	fw := NewGovernanceFirewall(eval, nil)

	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:  "risky-tool",
		SessionID: "sess-5",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-canonical")
}

func TestGovernanceFirewall_InterceptPlan(t *testing.T) {
	eval := &smartMockEvaluator{
		decisions: map[string]string{
			"tool-pass":    string(contracts.VerdictAllow),
			"tool-fail":    string(contracts.VerdictDeny),
			"tool-pending": string(contracts.VerdictEscalate),
		},
	}
	fw := NewGovernanceFirewall(eval, nil)

	planPass := ToolExecutionPlan{
		PlanID: "plan-1",
		Steps: []ToolExecutionRequest{
			{ToolName: "tool-pass"},
			{ToolName: "tool-pass"},
		},
	}
	decision, err := fw.InterceptPlan(context.Background(), planPass)
	require.NoError(t, err)
	assert.Equal(t, string(contracts.VerdictAllow), decision.Status)
	assert.Len(t, decision.Decisions, 2)

	planFail := ToolExecutionPlan{
		PlanID: "plan-2",
		Steps: []ToolExecutionRequest{
			{ToolName: "tool-pass"},
			{ToolName: "tool-fail"},
			{ToolName: "tool-pending"},
		},
	}
	decision, err = fw.InterceptPlan(context.Background(), planFail)
	require.NoError(t, err)
	assert.Equal(t, string(contracts.VerdictDeny), decision.Status)

	planPending := ToolExecutionPlan{
		PlanID: "plan-3",
		Steps: []ToolExecutionRequest{
			{ToolName: "tool-pass"},
			{ToolName: "tool-pending"},
		},
	}
	decision, err = fw.InterceptPlan(context.Background(), planPending)
	require.NoError(t, err)
	assert.Equal(t, string(contracts.VerdictEscalate), decision.Status)
}

func TestGovernanceFirewall_InterceptPlanRawPendingAggregatesAsEscalate(t *testing.T) {
	eval := &smartMockEvaluator{decisions: map[string]string{
		"allow":       string(contracts.VerdictAllow),
		"raw-pending": "PENDING",
		"deny":        string(contracts.VerdictDeny),
	}}
	fw := NewGovernanceFirewall(eval, nil)

	decision, err := fw.InterceptPlan(context.Background(), ToolExecutionPlan{
		PlanID: "plan-raw-pending",
		Steps: []ToolExecutionRequest{
			{ToolName: "allow"},
			{ToolName: "raw-pending"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, string(contracts.VerdictEscalate), decision.Status)

	decision, err = fw.InterceptPlan(context.Background(), ToolExecutionPlan{
		PlanID: "plan-deny-wins-over-raw-pending",
		Steps: []ToolExecutionRequest{
			{ToolName: "raw-pending"},
			{ToolName: "deny"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, string(contracts.VerdictDeny), decision.Status)
}

func TestGovernanceFirewall_AuthoritativeCatalogRejectsUnclassifiedTool(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*GovernanceFirewall) error
	}{
		{
			name: "single execution",
			run: func(fw *GovernanceFirewall) error {
				return fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{ToolName: "unknown.tool"})
			},
		},
		{
			name: "plan execution",
			run: func(fw *GovernanceFirewall) error {
				_, err := fw.InterceptPlan(context.Background(), ToolExecutionPlan{
					PlanID: "plan-unclassified",
					Steps:  []ToolExecutionRequest{{ToolName: "unknown.tool"}},
				})
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evaluated := false
			fw := NewGovernanceFirewall(&capturingEvaluator{
				verdict: string(contracts.VerdictAllow),
				capture: func(guardian.DecisionRequest) { evaluated = true },
			}, NewToolCatalog())
			err := tc.run(fw)
			require.Error(t, err)
			assert.Contains(t, err.Error(), `tool "unknown.tool" is not classified`)
			assert.False(t, evaluated, "unclassified tool reached evaluator")
		})
	}
}

func TestGovernanceFirewall_InterceptPlanRejectsCallerSecurityContext(t *testing.T) {
	for _, key := range []string{guardian.ContextDestination, guardian.ContextEgressDestinationRequired} {
		t.Run(key, func(t *testing.T) {
			evaluated := false
			fw := NewGovernanceFirewall(&capturingEvaluator{
				verdict: string(contracts.VerdictAllow),
				capture: func(guardian.DecisionRequest) { evaluated = true },
			}, nil)
			_, err := fw.InterceptPlan(context.Background(), ToolExecutionPlan{
				PlanID: "plan-reserved-context",
				Steps: []ToolExecutionRequest{{
					ToolName:  "local.tool",
					Arguments: map[string]any{key: true},
					SessionID: "session-fallback",
				}},
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "reserved security context argument")
			assert.False(t, evaluated, "reserved context reached the evaluator")
		})
	}
}

func TestGovernanceFirewall_InterceptPlanBindsTrustedIdentityAndClassification(t *testing.T) {
	catalog := NewToolCatalog()
	require.NoError(t, catalog.Register(context.Background(), ToolRef{
		Name:        "company.artifact.update",
		EffectClass: "E2",
		RiskTier:    contracts.RiskTierMedium,
	}))

	var captured guardian.DecisionRequest
	fw := NewGovernanceFirewall(&capturingEvaluator{
		verdict: string(contracts.VerdictAllow),
		capture: func(req guardian.DecisionRequest) { captured = req },
	}, catalog)
	decision, err := fw.InterceptPlan(context.Background(), ToolExecutionPlan{
		PlanID: "plan-trusted-bindings",
		Steps: []ToolExecutionRequest{{
			ToolName:       "company.artifact.update",
			Arguments:      map[string]any{"artifact_id": "artifact-1"},
			SessionID:      "session-fallback",
			PrincipalID:    "authenticated-principal",
			CredentialHash: "sha256:credential",
		}},
	})
	require.NoError(t, err)
	require.NotNil(t, decision)
	assert.Equal(t, string(contracts.VerdictAllow), decision.Status)
	assert.Equal(t, "authenticated-principal", captured.Principal)
	assert.Equal(t, "company.artifact.update", captured.Resource)
	assert.Equal(t, "sha256:credential", captured.Context[guardian.ContextCredentialHash])
	assert.Equal(t, "E2", captured.Context[guardian.ContextEffectClass])
	assert.Equal(t, true, captured.Context[guardian.ContextSecurityTrusted])
	assert.Equal(t, "session-fallback", captured.Context[guardian.ContextSessionID])
	assert.Equal(t, "artifact-1", captured.Context["artifact_id"])
	_, hasDestination := captured.Context[guardian.ContextDestination]
	assert.False(t, hasDestination, "local E2 tool acquired an egress destination")
	_, requiresDestination := captured.Context[guardian.ContextEgressDestinationRequired]
	assert.False(t, requiresDestination, "local E2 tool acquired an egress requirement")
}

func TestGovernanceFirewall_BindsCatalogOwnedEgressContextForE0Tool(t *testing.T) {
	catalog := NewToolCatalog()
	require.NoError(t, catalog.Register(context.Background(), ToolRef{
		Name:                      "github.read_pr",
		EffectClass:               "E0",
		RiskTier:                  contracts.RiskTierLow,
		EgressDestinationRequired: true,
		EgressDestination:         "api.github.com",
	}))

	var captured guardian.DecisionRequest
	fw := NewGovernanceFirewall(&capturingEvaluator{
		verdict: string(contracts.VerdictAllow),
		capture: func(req guardian.DecisionRequest) { captured = req },
	}, catalog)
	require.NoError(t, fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:  "github.read_pr",
		SessionID: "session-github-read",
	}))
	assert.Equal(t, "E0", captured.Context[guardian.ContextEffectClass])
	assert.Equal(t, true, captured.Context[guardian.ContextEgressDestinationRequired])
	assert.Equal(t, "api.github.com", captured.Context[guardian.ContextDestination])
}
