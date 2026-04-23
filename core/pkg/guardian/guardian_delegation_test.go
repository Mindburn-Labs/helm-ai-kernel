package guardian

import (
	"context"
	"testing"
	"time"

	pkg_artifact "github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupGuardianWithDelegation creates a Guardian with a delegation store
// and a permissive PRG (empty rule → always pass) for delegation-focused tests.
func setupGuardianWithDelegation(t *testing.T) (*Guardian, *identity.InMemoryDelegationStore) {
	t.Helper()

	mockStore := NewMockStore()
	registry := pkg_artifact.NewRegistry(mockStore, nil)
	signer := &MockSigner{}
	ruleGraph := prg.NewGraph()

	// Allow EXECUTE_TOOL via PRG so we reach Gate 5 without PRG blocking
	_ = ruleGraph.AddRule("allowed_tool", prg.RequirementSet{
		ID:           "allow-all",
		Requirements: []prg.Requirement{},
	})

	g := NewGuardian(signer, ruleGraph, registry)

	delegationStore := identity.NewInMemoryDelegationStore()
	g.SetDelegationStore(delegationStore)

	return g, delegationStore
}

func TestGuardian_Delegation_ValidSession_Allow(t *testing.T) {
	g, store := setupGuardianWithDelegation(t)
	ctx := context.Background()
	now := time.Now()

	// Create a valid delegation session
	session := identity.NewDelegationSession(
		"sess-valid", "user-alice", "agent-bot1",
		"nonce-valid", "sha256:policy1", "trust-root-1",
		100, now.Add(1*time.Hour), true, nil,
	)
	session.AddAllowedTool("allowed_tool")
	_ = session.AddCapability(identity.CapabilityGrant{
		Resource: "allowed_tool",
		Actions:  []string{"EXECUTE_TOOL"},
	})
	_ = store.Store(session)

	req := DecisionRequest{
		Principal: "agent-bot1",
		Action:    "EXECUTE_TOOL",
		Resource:  "allowed_tool",
		Context: map[string]interface{}{
			"delegation_session_id": "sess-valid",
		},
	}

	decision, err := g.EvaluateDecision(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "ALLOW", decision.Verdict)
	assert.Empty(t, decision.ReasonCode)
}

func TestGuardian_Delegation_ExpiredSession_Deny(t *testing.T) {
	g, store := setupGuardianWithDelegation(t)
	ctx := context.Background()
	now := time.Now()

	// Create an expired session
	session := identity.NewDelegationSession(
		"sess-expired", "user-alice", "agent-bot1",
		"nonce-expired", "sha256:policy1", "trust-root-1",
		100, now.Add(-1*time.Hour), true, nil, // already expired
	)
	session.AddAllowedTool("allowed_tool")
	_ = store.Store(session)

	req := DecisionRequest{
		Principal: "agent-bot1",
		Action:    "EXECUTE_TOOL",
		Resource:  "allowed_tool",
		Context: map[string]interface{}{
			"delegation_session_id": "sess-expired",
		},
	}

	decision, err := g.EvaluateDecision(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "DENY", decision.Verdict)
	assert.Equal(t, string(contracts.ReasonDelegationInvalid), decision.ReasonCode)
}

func TestGuardian_Delegation_MissingSession_Deny(t *testing.T) {
	g, _ := setupGuardianWithDelegation(t)
	ctx := context.Background()

	req := DecisionRequest{
		Principal: "agent-bot1",
		Action:    "EXECUTE_TOOL",
		Resource:  "allowed_tool",
		Context: map[string]interface{}{
			"delegation_session_id": "nonexistent",
		},
	}

	decision, err := g.EvaluateDecision(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "DENY", decision.Verdict)
	assert.Equal(t, string(contracts.ReasonDelegationInvalid), decision.ReasonCode)
}

func TestGuardian_Delegation_ToolScopeViolation_Deny(t *testing.T) {
	g, store := setupGuardianWithDelegation(t)
	ctx := context.Background()
	now := time.Now()

	// Session only allows "allowed_tool"
	session := identity.NewDelegationSession(
		"sess-scope", "user-alice", "agent-bot1",
		"nonce-scope", "sha256:policy1", "trust-root-1",
		100, now.Add(1*time.Hour), true, nil,
	)
	session.AddAllowedTool("allowed_tool")
	_ = store.Store(session)

	// Request a different tool
	req := DecisionRequest{
		Principal: "agent-bot1",
		Action:    "EXECUTE_TOOL",
		Resource:  "forbidden_tool",
		Context: map[string]interface{}{
			"delegation_session_id": "sess-scope",
		},
	}

	decision, err := g.EvaluateDecision(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "DENY", decision.Verdict)
	assert.Equal(t, string(contracts.ReasonDelegationScopeViolation), decision.ReasonCode)
	assert.Contains(t, decision.Reason, "forbidden_tool")
}

func TestGuardian_Delegation_RevokedSession_Deny(t *testing.T) {
	g, store := setupGuardianWithDelegation(t)
	ctx := context.Background()
	now := time.Now()

	session := identity.NewDelegationSession(
		"sess-revoked", "user-alice", "agent-bot1",
		"nonce-revoked", "sha256:policy1", "trust-root-1",
		100, now.Add(1*time.Hour), true, nil,
	)
	session.AddAllowedTool("allowed_tool")
	_ = store.Store(session)
	_ = store.Revoke("sess-revoked")

	req := DecisionRequest{
		Principal: "agent-bot1",
		Action:    "EXECUTE_TOOL",
		Resource:  "allowed_tool",
		Context: map[string]interface{}{
			"delegation_session_id": "sess-revoked",
		},
	}

	decision, err := g.EvaluateDecision(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "DENY", decision.Verdict)
	assert.Equal(t, string(contracts.ReasonDelegationInvalid), decision.ReasonCode)
}

func TestGuardian_Delegation_NoDelegationStore_Passthrough(t *testing.T) {
	// Guardian without delegation store should ignore delegation context
	mockStore := NewMockStore()
	registry := pkg_artifact.NewRegistry(mockStore, nil)
	signer := &MockSigner{}
	ruleGraph := prg.NewGraph()
	_ = ruleGraph.AddRule("allowed_tool", prg.RequirementSet{
		ID:           "allow-all",
		Requirements: []prg.Requirement{},
	})

	g := NewGuardian(signer, ruleGraph, registry)
	// No SetDelegationStore

	ctx := context.Background()
	req := DecisionRequest{
		Principal: "agent-bot1",
		Action:    "EXECUTE_TOOL",
		Resource:  "allowed_tool",
		Context: map[string]interface{}{
			"delegation_session_id": "some-session",
		},
	}

	decision, err := g.EvaluateDecision(ctx, req)
	require.NoError(t, err)
	// Should pass through to PRG evaluation without delegation check
	assert.Equal(t, "ALLOW", decision.Verdict)
}

func TestGuardian_Delegation_NoDelegationContext_Passthrough(t *testing.T) {
	g, _ := setupGuardianWithDelegation(t)
	ctx := context.Background()

	// No delegation_session_id in context
	req := DecisionRequest{
		Principal: "agent-bot1",
		Action:    "EXECUTE_TOOL",
		Resource:  "allowed_tool",
		Context:   map[string]interface{}{},
	}

	decision, err := g.EvaluateDecision(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "ALLOW", decision.Verdict)
}

func TestGuardian_Delegation_ActionScopeViolation_Deny(t *testing.T) {
	g, store := setupGuardianWithDelegation(t)
	ctx := context.Background()
	now := time.Now()

	session := identity.NewDelegationSession(
		"sess-action", "user-alice", "agent-bot1",
		"nonce-action", "sha256:policy1", "trust-root-1",
		100, now.Add(1*time.Hour), true, nil,
	)
	session.AddAllowedTool("allowed_tool")
	_ = session.AddCapability(identity.CapabilityGrant{
		Resource: "allowed_tool",
		Actions:  []string{"READ"}, // Only READ, not EXECUTE_TOOL
	})
	_ = store.Store(session)

	req := DecisionRequest{
		Principal: "agent-bot1",
		Action:    "EXECUTE_TOOL",
		Resource:  "allowed_tool",
		Context: map[string]interface{}{
			"delegation_session_id": "sess-action",
		},
	}

	decision, err := g.EvaluateDecision(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "DENY", decision.Verdict)
	assert.Equal(t, string(contracts.ReasonDelegationScopeViolation), decision.ReasonCode)
}
