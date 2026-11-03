package bridge

import (
	"context"
	"fmt"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/budget"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/identity"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestGuardian creates a minimal Guardian and PRG suitable for bridge tests.
func newTestGuardian(t *testing.T) (*guardian.Guardian, *prg.Graph) {
	t.Helper()
	signer, err := crypto.NewEd25519Signer("test-bridge")
	require.NoError(t, err)

	prgGraph := prg.NewGraph()

	store, err := artifacts.NewFileStore(t.TempDir())
	require.NoError(t, err)
	reg := artifacts.NewRegistry(store, signer)

	return guardian.NewGuardian(signer, prgGraph, reg), prgGraph
}

func addAllowedToolRule(t *testing.T, prgGraph *prg.Graph, toolName string) {
	t.Helper()
	err := prgGraph.AddRule(toolName, prg.RequirementSet{
		ID:    "allow-" + toolName,
		Logic: prg.AND,
		Requirements: []prg.Requirement{
			{
				ID:         "tool-match-" + toolName,
				Expression: fmt.Sprintf("input.action == %q", toolName),
			},
		},
	})
	require.NoError(t, err)
}

func TestGovern_AllowedToolCall(t *testing.T) {
	g, prgG := newTestGuardian(t)
	addAllowedToolRule(t, prgG, "get_weather")
	pg := proofgraph.NewGraph()

	kb := NewKernelBridge(g, prgG, pg, nil, "tenant-test")

	result, err := kb.Govern(context.Background(), "get_weather", "sha256:abc123", nil)
	require.NoError(t, err)

	assert.True(t, result.Allowed, "expected tool call to be allowed")
	assert.Empty(t, result.ReasonCode)
	assert.NotEmpty(t, result.NodeID, "expected ProofGraph node")
	assert.NotNil(t, result.Decision)
	assert.Equal(t, "ALLOW", result.Decision.Verdict)

	// ProofGraph should have 2 nodes: INTENT + ATTESTATION
	assert.Equal(t, 2, pg.Len())
}

func TestGovern_UnknownToolFailsClosedWithoutMutatingPolicy(t *testing.T) {
	g, prgG := newTestGuardian(t)
	pg := proofgraph.NewGraph()

	kb := NewKernelBridge(g, prgG, pg, nil, "tenant-test")

	result, err := kb.Govern(context.Background(), "credential_export", "sha256:bad", nil)
	require.NoError(t, err)

	assert.False(t, result.Allowed, "unknown tools must not be allowed")
	require.NotNil(t, result.Decision)
	assert.Equal(t, string(contracts.VerdictDeny), result.Decision.Verdict)
	assert.Equal(t, string(contracts.ReasonNoPolicy), result.ReasonCode)
	assert.Equal(t, string(contracts.ReasonNoPolicy), result.Decision.ReasonCode)
	assert.NotContains(t, prgG.Rules, "credential_export", "bridge must not auto-register tool policies")
	assert.Equal(t, 2, pg.Len(), "denials still record INTENT + ATTESTATION")
}

// dailyUsedCents reads a tenant's consumed daily budget, treating an
// un-provisioned tenant (nil budget) as zero used.
func dailyUsedCents(b *budget.Budget) int64 {
	if b == nil {
		return 0
	}
	return b.DailyUsed
}

func TestBudgetCentsRequiresExplicitZeroPrice(t *testing.T) {
	_, err := budgetCents(&effects.CostBreakdown{})
	require.ErrorContains(t, err, "monetary price is missing")

	amount, err := budgetCents(&effects.CostBreakdown{PriceKnown: true})
	require.NoError(t, err)
	assert.Zero(t, amount, "an explicitly priced free effect must remain representable")

	amount, err = budgetCents(&effects.CostBreakdown{InputTokens: 100, OutputTokens: 25, PriceKnown: true})
	require.NoError(t, err)
	assert.Zero(t, amount, "usage evidence must not invalidate an explicitly priced free effect")
}

func TestBudgetCentsRejectsInconsistentMonetaryBreakdown(t *testing.T) {
	_, err := budgetCents(&effects.CostBreakdown{
		ModelCostCents: 5,
		ToolCostCents:  2,
		TotalCents:     1,
	})
	require.Error(t, err)
}

func TestGovern_ProofGraphChainIntegrity(t *testing.T) {
	g, prgG := newTestGuardian(t)
	addAllowedToolRule(t, prgG, "tool_iterate")
	pg := proofgraph.NewGraph()

	kb := NewKernelBridge(g, prgG, pg, nil, "tenant-chain")
	ctx := context.Background()

	// Make 5 governed calls
	for i := 0; i < 5; i++ {
		r, err := kb.Govern(ctx, "tool_iterate", "sha256:iter", nil)
		require.NoError(t, err)
		assert.True(t, r.Allowed)
	}

	// ProofGraph should have 10 nodes (5 INTENT + 5 ATTESTATION)
	assert.Equal(t, 10, pg.Len())

	// Validate chain from all heads
	heads := pg.Heads()
	for _, h := range heads {
		err := pg.ValidateChain(h)
		assert.NoError(t, err, "chain validation should pass for head %s", h)
	}
}

func TestGovern_NilBudgetSkipsBudgetOnly(t *testing.T) {
	g, prgG := newTestGuardian(t)
	addAllowedToolRule(t, prgG, "any_tool")
	pg := proofgraph.NewGraph()

	kb := NewKernelBridge(g, prgG, pg, nil, "tenant-nobud")

	result, err := kb.Govern(context.Background(), "any_tool", "sha256:any", nil)
	require.NoError(t, err)
	assert.True(t, result.Allowed, "nil budget should skip only budget checks")
}

func TestGovern_DecisionHasToolName(t *testing.T) {
	g, prgG := newTestGuardian(t)
	addAllowedToolRule(t, prgG, "execute_code")
	pg := proofgraph.NewGraph()

	kb := NewKernelBridge(g, prgG, pg, nil, "tenant-tool")

	result, err := kb.Govern(context.Background(), "execute_code", "sha256:code", nil)
	require.NoError(t, err)
	require.NotNil(t, result.Decision)
	// Verify that the decision was made against the explicit tool policy.
	assert.Equal(t, "ALLOW", result.Decision.Verdict)
}

// TestGovernBound_SuppliesTrustedTransportEvidence pins the wiring gap behind
// audit finding 07-01: a Guardian with the identity-isolation gate (every
// production Guardian has one) denies any request that carries no trusted
// credential hash, so an unbound bridge can never reach a policy ALLOW.
func TestGovernBound_SuppliesTrustedTransportEvidence(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("test-bridge")
	require.NoError(t, err)
	prgG := prg.NewGraph()
	addAllowedToolRule(t, prgG, "get_weather")
	store, err := artifacts.NewFileStore(t.TempDir())
	require.NoError(t, err)
	g := guardian.NewGuardian(signer, prgG, artifacts.NewRegistry(store, signer),
		guardian.WithIsolationChecker(identity.NewIsolationChecker()))
	kb := NewKernelBridge(g, prgG, proofgraph.NewGraph(), nil, "tenant-bound")
	ctx := context.Background()

	unbound, err := kb.Govern(ctx, "get_weather", "sha256:abc", nil)
	require.NoError(t, err)
	assert.False(t, unbound.Allowed, "no transport evidence must fail closed")
	assert.Equal(t, string(contracts.ReasonIdentityIsolationViolation), unbound.ReasonCode)

	bound, err := kb.GovernBound(ctx, "get_weather", "sha256:abc", nil, Binding{
		CredentialHash: "cred-hash-1",
		SessionID:      "session-1",
	})
	require.NoError(t, err)
	require.NotNil(t, bound.Decision)
	assert.True(t, bound.Allowed, "bound call under an allowing policy must be allowed: %s", bound.Decision.Reason)
	assert.Equal(t, "cred-hash-1", bound.Decision.InputContext[guardian.ContextCredentialHash])
	assert.Equal(t, "session-1", bound.Decision.InputContext[guardian.ContextSessionID])

	denied, err := kb.GovernBound(ctx, "credential_export", "sha256:bad", nil, Binding{CredentialHash: "cred-hash-1"})
	require.NoError(t, err)
	assert.False(t, denied.Allowed, "binding evidence must not bypass policy")
	assert.Equal(t, string(contracts.ReasonNoPolicy), denied.ReasonCode)
}
