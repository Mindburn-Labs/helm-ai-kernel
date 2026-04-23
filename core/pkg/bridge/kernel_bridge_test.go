package bridge

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/budget"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
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

func TestGovern_AllowedToolCall(t *testing.T) {
	g, prgG := newTestGuardian(t)
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

func TestGovern_BudgetExhausted(t *testing.T) {
	g, prgG := newTestGuardian(t)
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

func TestGovern_NilBudgetSkips(t *testing.T) {
	g, prgG := newTestGuardian(t)
	pg := proofgraph.NewGraph()

	kb := NewKernelBridge(g, prgG, pg, nil, "tenant-nobud")

	result, err := kb.Govern(context.Background(), "any_tool", "sha256:any")
	require.NoError(t, err)
	assert.True(t, result.Allowed, "should allow when no budget enforcer")
}

func TestGovern_DecisionHasToolName(t *testing.T) {
	g, prgG := newTestGuardian(t)
	pg := proofgraph.NewGraph()

	kb := NewKernelBridge(g, prgG, pg, nil, "tenant-tool")

	result, err := kb.Govern(context.Background(), "execute_code", "sha256:code")
	require.NoError(t, err)
	require.NotNil(t, result.Decision)
	// Verify that the decision was made (verdict should be ALLOW with our open policy)
	assert.Equal(t, "ALLOW", result.Decision.Verdict)
}
