package kernel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ============================================================================
// Section F: Concurrency Artifacts Tests
// ============================================================================

func TestDependencyGraph(t *testing.T) {
	t.Run("create and finalize", func(t *testing.T) {
		graph := NewDependencyGraph("graph-1", "reducer-1")
		require.NotNil(t, graph)
		require.Equal(t, "graph-1", graph.GraphID)
		require.Equal(t, "reducer-1", graph.ReducerID)

		// Add nodes
		graph.AddNode(DependencyNode{
			NodeID:      "node-1",
			NodeType:    "INPUT",
			ContentHash: "abc123",
			ProducedAt:  time.Now().UnixMilli(),
		})
		graph.AddNode(DependencyNode{
			NodeID:      "node-2",
			NodeType:    "OUTPUT",
			DependsOn:   []string{"node-1"},
			ContentHash: "def456",
			ProducedAt:  time.Now().UnixMilli(),
		})

		// Add edge
		graph.AddEdge("node-1", "node-2", "DATA")

		// Finalize
		graph.Finalize()

		require.NotEmpty(t, graph.Hash)
		require.Contains(t, graph.RootNodes, "node-1")
		require.Contains(t, graph.LeafNodes, "node-2")
	})

	t.Run("hash is deterministic", func(t *testing.T) {
		graph1 := NewDependencyGraph("g1", "r1")
		graph1.AddNode(DependencyNode{NodeID: "a", NodeType: "X", ContentHash: "h1"})
		graph1.AddNode(DependencyNode{NodeID: "b", NodeType: "Y", ContentHash: "h2"})
		graph1.AddEdge("a", "b", "DATA")
		graph1.Finalize()

		graph2 := NewDependencyGraph("g2", "r2")
		graph2.AddNode(DependencyNode{NodeID: "a", NodeType: "X", ContentHash: "h1"})
		graph2.AddNode(DependencyNode{NodeID: "b", NodeType: "Y", ContentHash: "h2"})
		graph2.AddEdge("a", "b", "DATA")
		graph2.Finalize()

		require.Equal(t, graph1.Hash, graph2.Hash)
	})
}

func TestAttemptIndex(t *testing.T) {
	t.Run("record attempts", func(t *testing.T) {
		idx := NewAttemptIndex("idx-1", "op-1", 3)
		require.NotNil(t, idx)
		require.Equal(t, 3, idx.MaxAttempts)
		require.True(t, idx.CanRetry())

		// First attempt fails
		idx.RecordAttempt(false, "ERR_TIMEOUT", "connection timed out")
		require.Equal(t, 1, idx.CurrentIndex)
		require.True(t, idx.CanRetry())

		last := idx.LastAttempt()
		require.NotNil(t, last)
		require.False(t, last.Success)
		require.Equal(t, "ERR_TIMEOUT", last.ErrorCode)
		require.NotEmpty(t, last.ErrorHash)

		// Second attempt fails
		idx.RecordAttempt(false, "ERR_TIMEOUT", "connection timed out")
		require.Equal(t, 2, idx.CurrentIndex)
		require.True(t, idx.CanRetry())

		// Third attempt succeeds
		idx.RecordAttempt(true, "", "")
		require.Equal(t, 3, idx.CurrentIndex)
		require.False(t, idx.CanRetry()) // Max reached

		last = idx.LastAttempt()
		require.True(t, last.Success)
	})
}

func TestRetrySchedule(t *testing.T) {
	t.Run("fixed strategy", func(t *testing.T) {
		sched := NewRetrySchedule("sched-1", "op-1", RetryStrategyFixed, 1000, 10000, 2.0)

		require.Equal(t, 1000, sched.ComputeDelay(0))
		require.Equal(t, 1000, sched.ComputeDelay(1))
		require.Equal(t, 1000, sched.ComputeDelay(5))
	})

	t.Run("linear strategy", func(t *testing.T) {
		sched := NewRetrySchedule("sched-2", "op-2", RetryStrategyLinear, 1000, 10000, 2.0)

		require.Equal(t, 1000, sched.ComputeDelay(0))   // 1 * 1000
		require.Equal(t, 2000, sched.ComputeDelay(1))   // 2 * 1000
		require.Equal(t, 5000, sched.ComputeDelay(4))   // 5 * 1000
		require.Equal(t, 10000, sched.ComputeDelay(10)) // Capped at max
	})

	t.Run("exponential strategy", func(t *testing.T) {
		sched := NewRetrySchedule("sched-3", "op-3", RetryStrategyExponential, 1000, 10000, 2.0)

		require.Equal(t, 1000, sched.ComputeDelay(0))  // 1000 * 2^0
		require.Equal(t, 2000, sched.ComputeDelay(1))  // 1000 * 2^1
		require.Equal(t, 4000, sched.ComputeDelay(2))  // 1000 * 2^2
		require.Equal(t, 8000, sched.ComputeDelay(3))  // 1000 * 2^3
		require.Equal(t, 10000, sched.ComputeDelay(4)) // Capped at max
	})

	t.Run("schedule next run", func(t *testing.T) {
		sched := NewRetrySchedule("sched-4", "op-4", RetryStrategyFixed, 500, 10000, 1.0)
		base := time.Now()

		next := sched.ScheduleNextRun(base, 0)
		require.Equal(t, base.Add(500*time.Millisecond), next)
		require.Len(t, sched.ScheduledRuns, 1)
	})
}

func TestExecutionTrace(t *testing.T) {
	t.Run("create and add entries", func(t *testing.T) {
		trace := NewExecutionTrace("trace-1", "reducer-1")
		require.NotNil(t, trace)

		trace.AddEntry("evt-1", "StateChange", "in-hash-1", "out-hash-1")
		trace.AddEntry("evt-2", "Effect", "in-hash-2", "out-hash-2")

		require.Len(t, trace.Entries, 2)
		require.Equal(t, 1, trace.Entries[0].StepNum)
		require.Equal(t, 2, trace.Entries[1].StepNum)

		trace.Finalize()
		require.NotEmpty(t, trace.Hash)
	})

	t.Run("verify determinism", func(t *testing.T) {
		trace1 := NewExecutionTrace("t1", "r1")
		trace1.AddEntry("e1", "X", "ih1", "oh1")
		trace1.AddEntry("e2", "Y", "ih2", "oh2")

		trace2 := NewExecutionTrace("t2", "r2")
		trace2.AddEntry("e1", "X", "ih1", "oh1")
		trace2.AddEntry("e2", "Y", "ih2", "oh2")

		require.True(t, trace1.VerifyDeterminism(trace2))

		// Modify trace2
		trace2.Entries[0].EventID = "different"
		require.False(t, trace1.VerifyDeterminism(trace2))
	})
}

func TestConcurrencyArtifactValidation(t *testing.T) {
	t.Run("valid dependency graph", func(t *testing.T) {
		graph := NewDependencyGraph("g1", "r1")
		graph.Finalize()

		artifact := &ConcurrencyArtifact{
			Type:            ConcurrencyArtifactDependencyGraph,
			DependencyGraph: graph,
		}
		issues := ValidateConcurrencyArtifact(artifact)
		require.Empty(t, issues)
	})

	t.Run("nil dependency graph", func(t *testing.T) {
		artifact := &ConcurrencyArtifact{
			Type:            ConcurrencyArtifactDependencyGraph,
			DependencyGraph: nil,
		}
		issues := ValidateConcurrencyArtifact(artifact)
		require.Len(t, issues, 1)
		require.Contains(t, issues[0], "nil")
	})

	t.Run("valid attempt index", func(t *testing.T) {
		artifact := &ConcurrencyArtifact{
			Type:         ConcurrencyArtifactAttemptIndex,
			AttemptIndex: NewAttemptIndex("i1", "o1", 3),
		}
		issues := ValidateConcurrencyArtifact(artifact)
		require.Empty(t, issues)
	})
}
