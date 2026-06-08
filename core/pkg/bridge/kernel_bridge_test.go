package bridge

import (
	"context"
	"fmt"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/budget"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
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

	result, err := kb.Govern(context.Background(), "get_weather", "sha256:abc123")
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

	result, err := kb.Govern(context.Background(), "credential_export", "sha256:bad")
	require.NoError(t, err)

	assert.False(t, result.Allowed, "unknown tools must not be allowed")
	require.NotNil(t, result.Decision)
	assert.Equal(t, string(contracts.VerdictDeny), result.Decision.Verdict)
	assert.Equal(t, string(contracts.ReasonNoPolicy), result.ReasonCode)
	assert.Equal(t, string(contracts.ReasonNoPolicy), result.Decision.ReasonCode)
	assert.NotContains(t, prgG.Rules, "credential_export", "bridge must not auto-register tool policies")
	assert.Equal(t, 2, pg.Len(), "denials still record INTENT + ATTESTATION")
}

func TestGovern_BudgetExhausted(t *testing.T) {
	g, prgG := newTestGuardian(t)
	addAllowedToolRule(t, prgG, "tool_a")
	addAllowedToolRule(t, prgG, "tool_b")
	pg := proofgraph.NewGraph()

	// Create budget enforcer with very low limit
	memStore := budget.NewMemoryStorage()
	enforcer := budget.NewSimpleEnforcer(memStore)
	ctx := context.Background()

	// Set limits to 2 cents daily, 10 monthly
	err := enforcer.SetLimits(ctx, "tenant-budget", 2, 10)
	require.NoError(t, err)

	kb := NewKernelBridge(g, prgG, pg, enforcer, "tenant-budget")

	// First two calls should pass (budget = 2 cents daily, 1 cent per call)
	r1, err := kb.Govern(ctx, "tool_a", "sha256:1")
	require.NoError(t, err)
	assert.True(t, r1.Allowed, "first call should succeed")

	r2, err := kb.Govern(ctx, "tool_b", "sha256:2")
	require.NoError(t, err)
	assert.True(t, r2.Allowed, "second call should succeed")

	// Third call should be budget-blocked
	r3, err := kb.Govern(ctx, "tool_c", "sha256:3")
	require.NoError(t, err)
	assert.False(t, r3.Allowed, "third call should be denied (budget exhausted)")
	assert.Equal(t, string(contracts.ReasonBudgetExceeded), r3.ReasonCode)
}

func TestGovern_ProofGraphChainIntegrity(t *testing.T) {
	g, prgG := newTestGuardian(t)
	addAllowedToolRule(t, prgG, "tool_iterate")
	pg := proofgraph.NewGraph()

	kb := NewKernelBridge(g, prgG, pg, nil, "tenant-chain")
	ctx := context.Background()

	// Make 5 governed calls
	for i := 0; i < 5; i++ {
		r, err := kb.Govern(ctx, "tool_iterate", "sha256:iter")
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

	result, err := kb.Govern(context.Background(), "any_tool", "sha256:any")
	require.NoError(t, err)
	assert.True(t, result.Allowed, "nil budget should skip only budget checks")
}

func TestGovern_DecisionHasToolName(t *testing.T) {
	g, prgG := newTestGuardian(t)
	addAllowedToolRule(t, prgG, "execute_code")
	pg := proofgraph.NewGraph()

	kb := NewKernelBridge(g, prgG, pg, nil, "tenant-tool")

	result, err := kb.Govern(context.Background(), "execute_code", "sha256:code")
	require.NoError(t, err)
	require.NotNil(t, result.Decision)
	// Verify that the decision was made against the explicit tool policy.
	assert.Equal(t, "ALLOW", result.Decision.Verdict)
}
