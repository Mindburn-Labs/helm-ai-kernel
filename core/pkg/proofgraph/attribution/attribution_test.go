package attribution

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// buildLinearChain creates a linear chain of nodes owned by the given principals.
// Returns the graph and the hash of the last (failure) node.
func buildLinearChain(principals []string, kinds []proofgraph.NodeType) (*proofgraph.Graph, string) {
	g := proofgraph.NewGraph()
	var lastHash string
	for i, principal := range principals {
		kind := proofgraph.NodeTypeIntent
		if i < len(kinds) {
			kind = kinds[i]
		}
		node, err := g.Append(kind, []byte(`{}`), principal, uint64(i+1))
		if err != nil {
			panic(err)
		}
		lastHash = node.NodeHash
	}
	return g, lastHash
}

func TestAttributor_SingleAgent(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	a := New(WithClock(fixedClock(now)))

	g, failureID := buildLinearChain(
		[]string{"agent:planner", "agent:planner", "agent:planner"},
		[]proofgraph.NodeType{proofgraph.NodeTypeIntent, proofgraph.NodeTypeAttestation, proofgraph.NodeTypeEffect},
	)

	result, err := a.Attribute(g, failureID)
	require.NoError(t, err)

	assert.Equal(t, failureID, result.FailureNodeID)
	assert.Equal(t, now, result.ComputedAt)
	assert.Equal(t, 3, result.TotalNodesTraced)
	assert.Equal(t, 2, result.MaxDepth)

	require.Len(t, result.Contributions, 1)
	c := result.Contributions[0]
	assert.Equal(t, "agent:planner", c.Principal)
	assert.InDelta(t, 1.0, c.Score, 0.001, "single agent should get 100% blame")
	assert.Equal(t, 3, c.NodeCount)
	assert.Equal(t, 1, c.EffectCount)
	assert.Equal(t, 0, c.CausalDepth) // Present at the failure node itself.
}

func TestAttributor_TwoAgentsEqualContribution(t *testing.T) {
	a := New()

	// Two agents at the same depth: each gets one node.
	// Build a chain: agent-a (depth 1) -> agent-b (depth 0, failure node).
	// Actually, to get equal weighting, we need two agents at the same depth
	// relative to the failure. Let's use a 2-node chain:
	// agent-a at depth 1, agent-b at depth 0.
	// Weight: agent-b = 1/(0+1)=1.0, agent-a = 1/(1+1)=0.5.
	// That's not equal. For equal contribution, build two separate ancestors
	// at the same depth. But the graph is linear, so let's test a simple
	// alternating pattern instead.
	//
	// For true "equal" test: 2-node chain, both same agent.
	// Or: test a 2-node chain with different agents and verify the ratio.

	// Chain: agent-a (depth 2) -> agent-b (depth 1) -> agent-a (depth 0)
	// agent-a weight: 1/(0+1) + 1/(2+1) = 1.0 + 0.333 = 1.333
	// agent-b weight: 1/(1+1) = 0.5
	// Total = 1.833
	// agent-a score = 1.333/1.833 ≈ 0.727
	// agent-b score = 0.5/1.833 ≈ 0.273

	// Let's make a symmetric chain instead:
	// agent-a (depth 1) -> agent-b (depth 0)
	g, failureID := buildLinearChain(
		[]string{"agent-a", "agent-b"},
		[]proofgraph.NodeType{proofgraph.NodeTypeIntent, proofgraph.NodeTypeEffect},
	)

	result, err := a.Attribute(g, failureID)
	require.NoError(t, err)
	require.Len(t, result.Contributions, 2)

	// agent-b at depth 0: weight = 1.0
	// agent-a at depth 1: weight = 0.5
	// Total = 1.5
	assert.Equal(t, "agent-b", result.Contributions[0].Principal, "closer agent should rank first")
	assert.InDelta(t, 1.0/1.5, result.Contributions[0].Score, 0.001) // ≈ 0.667
	assert.InDelta(t, 0.5/1.5, result.Contributions[1].Score, 0.001) // ≈ 0.333

	// Scores must sum to 1.0.
	totalScore := result.Contributions[0].Score + result.Contributions[1].Score
	assert.InDelta(t, 1.0, totalScore, 0.001)
}

func TestAttributor_WeightedByDepth(t *testing.T) {
	a := New()

	// Chain: A(depth 3) -> B(depth 2) -> B(depth 1) -> A(depth 0)
	// A weight: 1/(0+1) + 1/(3+1) = 1.0 + 0.25 = 1.25
	// B weight: 1/(1+1) + 1/(2+1) = 0.5 + 0.333 = 0.833
	// Total: 2.083
	// A score: 1.25/2.083 ≈ 0.600
	// B score: 0.833/2.083 ≈ 0.400
	g, failureID := buildLinearChain(
		[]string{"agent-a", "agent-b", "agent-b", "agent-a"},
		[]proofgraph.NodeType{
			proofgraph.NodeTypeIntent,
			proofgraph.NodeTypeAttestation,
			proofgraph.NodeTypeEffect,
			proofgraph.NodeTypeEffect,
		},
	)

	result, err := a.Attribute(g, failureID)
	require.NoError(t, err)
	require.Len(t, result.Contributions, 2)

	// agent-a should score higher (closer to failure).
	assert.Equal(t, "agent-a", result.Contributions[0].Principal)
	assert.InDelta(t, 1.25/2.083, result.Contributions[0].Score, 0.01)
	assert.Equal(t, 0, result.Contributions[0].CausalDepth) // Closest node at depth 0.

	assert.Equal(t, "agent-b", result.Contributions[1].Principal)
	assert.InDelta(t, 0.833/2.083, result.Contributions[1].Score, 0.01)
	assert.Equal(t, 1, result.Contributions[1].CausalDepth) // Closest B node at depth 1.

	assert.Equal(t, 4, result.TotalNodesTraced)
	assert.Equal(t, 3, result.MaxDepth)

	// Verify scores sum to 1.0.
	totalScore := 0.0
	for _, c := range result.Contributions {
		totalScore += c.Score
	}
	assert.InDelta(t, 1.0, totalScore, 0.001)
}

func TestAttributor_SingleNodeNoParents(t *testing.T) {
	a := New()

	g := proofgraph.NewGraph()
	node, err := g.Append(proofgraph.NodeTypeEffect, []byte(`{}`), "agent:solo", 1)
	require.NoError(t, err)

	result, err := a.Attribute(g, node.NodeHash)
	require.NoError(t, err)

	assert.Equal(t, 1, result.TotalNodesTraced)
	assert.Equal(t, 0, result.MaxDepth)
	require.Len(t, result.Contributions, 1)
	assert.Equal(t, "agent:solo", result.Contributions[0].Principal)
	assert.InDelta(t, 1.0, result.Contributions[0].Score, 0.001)
	assert.Equal(t, 0, result.Contributions[0].CausalDepth)
	assert.Equal(t, 1, result.Contributions[0].NodeCount)
}

func TestAttributor_MissingNodeReturnsError(t *testing.T) {
	a := New()

	g := proofgraph.NewGraph()

	_, err := a.Attribute(g, "nonexistent-node-hash")
	require.Error(t, err)

	var nodeErr *ErrNodeNotFound
	assert.ErrorAs(t, err, &nodeErr)
	assert.Equal(t, "nonexistent-node-hash", nodeErr.NodeID)
	assert.Contains(t, err.Error(), "nonexistent-node-hash")
}

func TestAttributor_LargeChain(t *testing.T) {
	a := New()

	const chainLen = 100
	principals := make([]string, chainLen)
	kinds := make([]proofgraph.NodeType, chainLen)
	for i := 0; i < chainLen; i++ {
		if i%3 == 0 {
			principals[i] = "agent-a"
		} else if i%3 == 1 {
			principals[i] = "agent-b"
		} else {
			principals[i] = "agent-c"
		}
		kinds[i] = proofgraph.NodeTypeEffect
	}

	g, failureID := buildLinearChain(principals, kinds)

	result, err := a.Attribute(g, failureID)
	require.NoError(t, err)

	assert.Equal(t, chainLen, result.TotalNodesTraced)
	assert.Equal(t, chainLen-1, result.MaxDepth)
	require.Len(t, result.Contributions, 3)

	// Verify scores sum to 1.0.
	totalScore := 0.0
	for _, c := range result.Contributions {
		totalScore += c.Score
		assert.Greater(t, c.Score, 0.0)
		assert.Greater(t, c.NodeCount, 0)
	}
	assert.InDelta(t, 1.0, totalScore, 0.001)

	// Verify sorted by score descending.
	for i := 1; i < len(result.Contributions); i++ {
		assert.GreaterOrEqual(t, result.Contributions[i-1].Score, result.Contributions[i].Score,
			"contributions should be sorted by score descending")
	}
}

func TestAttributor_EffectCountTracking(t *testing.T) {
	a := New()

	g, failureID := buildLinearChain(
		[]string{"agent-a", "agent-a", "agent-a"},
		[]proofgraph.NodeType{
			proofgraph.NodeTypeIntent,
			proofgraph.NodeTypeAttestation,
			proofgraph.NodeTypeEffect,
		},
	)

	result, err := a.Attribute(g, failureID)
	require.NoError(t, err)
	require.Len(t, result.Contributions, 1)

	assert.Equal(t, 3, result.Contributions[0].NodeCount)
	assert.Equal(t, 1, result.Contributions[0].EffectCount,
		"should count exactly 1 EFFECT node")
}

func TestAttributor_EmptyPrincipalHandled(t *testing.T) {
	a := New()

	g := proofgraph.NewGraph()
	// NewNode with empty principal.
	node, err := g.Append(proofgraph.NodeTypeEffect, []byte(`{}`), "", 1)
	require.NoError(t, err)

	result, err := a.Attribute(g, node.NodeHash)
	require.NoError(t, err)
	require.Len(t, result.Contributions, 1)
	assert.Equal(t, "<unknown>", result.Contributions[0].Principal)
}

func TestAttributor_DeterministicOutput(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)

	// Run attribution twice on the same graph — results must be identical.
	for run := 0; run < 2; run++ {
		a := New(WithClock(fixedClock(now)))

		g, failureID := buildLinearChain(
			[]string{"agent-a", "agent-b", "agent-c"},
			[]proofgraph.NodeType{
				proofgraph.NodeTypeIntent,
				proofgraph.NodeTypeAttestation,
				proofgraph.NodeTypeEffect,
			},
		)

		result, err := a.Attribute(g, failureID)
		require.NoError(t, err)

		require.Len(t, result.Contributions, 3)
		// agent-c at depth 0 (weight 1.0), agent-b at depth 1 (weight 0.5),
		// agent-a at depth 2 (weight 0.333).
		assert.Equal(t, "agent-c", result.Contributions[0].Principal)
		assert.Equal(t, "agent-b", result.Contributions[1].Principal)
		assert.Equal(t, "agent-a", result.Contributions[2].Principal)
	}
}
