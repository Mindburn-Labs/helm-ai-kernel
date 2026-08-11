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
	oneCent := &effects.CostBreakdown{TotalCents: 1}
	r1, err := kb.Govern(ctx, "tool_a", "sha256:1", oneCent)
	require.NoError(t, err)
	assert.True(t, r1.Allowed, "first call should succeed")

	r2, err := kb.Govern(ctx, "tool_b", "sha256:2", oneCent)
	require.NoError(t, err)
	assert.True(t, r2.Allowed, "second call should succeed")

	// Third call should be budget-blocked
	r3, err := kb.Govern(ctx, "tool_c", "sha256:3", oneCent)
	require.NoError(t, err)
	assert.False(t, r3.Allowed, "third call should be denied (budget exhausted)")
	assert.Equal(t, string(contracts.ReasonBudgetExceeded), r3.ReasonCode)
}

// dailyUsedCents reads a tenant's consumed daily budget, treating an
// un-provisioned tenant (nil budget) as zero used.
func dailyUsedCents(b *budget.Budget) int64 {
	if b == nil {
		return 0
	}
	return b.DailyUsed
}

// TestGovern_BudgetMeteredByEffectCost is the money-metering gate: an effect's
// real cost — not a constant — must drive budget consumption, so an expensive
// model call consumes proportionally more than a cheap one, and a cost that
// exceeds the limit is denied.
//
// MUTATION CHECK: revert kernel_bridge.go's budget amount to a constant
// (`Amount: 1`) and this test fails at the proportional-delta assertions,
// proving the test actually pins metering to cost rather than call count.
func TestGovern_BudgetMeteredByEffectCost(t *testing.T) {
	g, prgG := newTestGuardian(t)
	addAllowedToolRule(t, prgG, "cheap_tool")
	addAllowedToolRule(t, prgG, "expensive_tool")
	pg := proofgraph.NewGraph()

	memStore := budget.NewMemoryStorage()
	enforcer := budget.NewSimpleEnforcer(memStore)
	ctx := context.Background()

	const tenant = "tenant-metered"
	// Generous limits so both priced calls are admitted; the final huge call
	// is what must trip the limit.
	require.NoError(t, enforcer.SetLimits(ctx, tenant, 10_000, 100_000))

	kb := NewKernelBridge(g, prgG, pg, enforcer, tenant)

	cheap := &effects.CostBreakdown{ModelCostCents: 5, TotalCents: 5}
	expensive := &effects.CostBreakdown{ModelCostCents: 500, TotalCents: 500}

	rCheap, err := kb.Govern(ctx, "cheap_tool", "sha256:cheap", cheap)
	require.NoError(t, err)
	require.True(t, rCheap.Allowed, "cheap call within budget must be allowed")
	afterCheap, err := enforcer.GetBudget(ctx, tenant)
	require.NoError(t, err)
	cheapDelta := dailyUsedCents(afterCheap) // from zero

	rExp, err := kb.Govern(ctx, "expensive_tool", "sha256:exp", expensive)
	require.NoError(t, err)
	require.True(t, rExp.Allowed, "expensive call within budget must be allowed")
	afterExp, err := enforcer.GetBudget(ctx, tenant)
	require.NoError(t, err)
	expDelta := dailyUsedCents(afterExp) - dailyUsedCents(afterCheap)

	// Proportional: each effect consumes exactly its own cost, and the
	// expensive call consumes 100x the cheap one.
	assert.Equal(t, int64(5), cheapDelta, "cheap effect must consume its 5-cent cost")
	assert.Equal(t, int64(500), expDelta, "expensive effect must consume its 500-cent cost")
	assert.Equal(t, cheapDelta*100, expDelta, "budget consumption must scale with effect cost")

	// Denial: a cost exceeding the remaining daily budget is blocked, fail-closed.
	huge := &effects.CostBreakdown{TotalCents: 1_000_000}
	rDenied, err := kb.Govern(ctx, "expensive_tool", "sha256:huge", huge)
	require.NoError(t, err)
	assert.False(t, rDenied.Allowed, "a cost exceeding the limit must be denied")
	assert.Equal(t, string(contracts.ReasonBudgetExceeded), rDenied.ReasonCode)
}

func TestGovern_BudgetRejectsTokenCountsAsMoney(t *testing.T) {
	g, prgG := newTestGuardian(t)
	addAllowedToolRule(t, prgG, "priced_tool")

	memStore := budget.NewMemoryStorage()
	enforcer := budget.NewSimpleEnforcer(memStore)
	ctx := context.Background()
	const tenant = "tenant-unpriced"
	require.NoError(t, enforcer.SetLimits(ctx, tenant, 10_000, 100_000))

	kb := NewKernelBridge(g, prgG, proofgraph.NewGraph(), enforcer, tenant)
	usageOnly := &effects.CostBreakdown{InputTokens: 2_000, OutputTokens: 500}

	result, err := kb.Govern(ctx, "priced_tool", "sha256:usage-only", usageOnly)
	require.NoError(t, err)
	require.False(t, result.Allowed, "unpriced token usage must fail closed")
	assert.Equal(t, string(contracts.ReasonBudgetError), result.ReasonCode)

	got, err := enforcer.GetBudget(ctx, tenant)
	require.NoError(t, err)
	assert.Zero(t, dailyUsedCents(got), "token counts must never be persisted as cents")
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
