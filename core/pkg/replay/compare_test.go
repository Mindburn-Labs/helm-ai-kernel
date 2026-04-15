package replay

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompareTraces_Identical(t *testing.T) {
	trace := []TraceEntry{
		{Action: "read", Resource: "file.txt", Verdict: "ALLOW"},
		{Action: "write", Resource: "db.users", Verdict: "DENY", Reason: "policy"},
		{Action: "execute", Resource: "cmd.deploy", Verdict: "ALLOW"},
	}

	diff := CompareTraces("session-a", trace, "session-b", trace)

	assert.True(t, diff.Identical)
	assert.Equal(t, "session-a", diff.SessionA)
	assert.Equal(t, "session-b", diff.SessionB)
	assert.Equal(t, 3, diff.TotalA)
	assert.Equal(t, 3, diff.TotalB)
	assert.Equal(t, 3, diff.MatchCount)
	assert.Equal(t, 0, diff.DivergentCount)
	assert.Equal(t, 0, diff.OnlyInA)
	assert.Equal(t, 0, diff.OnlyInB)
	assert.Empty(t, diff.Divergences)
}

func TestCompareTraces_DifferentVerdicts(t *testing.T) {
	traceA := []TraceEntry{
		{Action: "read", Resource: "file.txt", Verdict: "ALLOW"},
		{Action: "write", Resource: "db.users", Verdict: "DENY", Reason: "policy-v1"},
	}
	traceB := []TraceEntry{
		{Action: "read", Resource: "file.txt", Verdict: "ALLOW"},
		{Action: "write", Resource: "db.users", Verdict: "ALLOW", Reason: "policy-v2"},
	}

	diff := CompareTraces("a", traceA, "b", traceB)

	assert.False(t, diff.Identical)
	assert.Equal(t, 1, diff.MatchCount)
	assert.Equal(t, 1, diff.DivergentCount)
	assert.Equal(t, 0, diff.OnlyInA)
	assert.Equal(t, 0, diff.OnlyInB)
	require.Len(t, diff.Divergences, 1)

	d := diff.Divergences[0]
	assert.Equal(t, "write", d.Action)
	assert.Equal(t, "db.users", d.Resource)
	assert.Equal(t, "DENY", d.VerdictA)
	assert.Equal(t, "ALLOW", d.VerdictB)
	assert.Equal(t, "policy-v1", d.ReasonA)
	assert.Equal(t, "policy-v2", d.ReasonB)
}

func TestCompareTraces_OnlyInA(t *testing.T) {
	traceA := []TraceEntry{
		{Action: "read", Resource: "file.txt", Verdict: "ALLOW"},
		{Action: "delete", Resource: "file.txt", Verdict: "DENY"},
	}
	traceB := []TraceEntry{
		{Action: "read", Resource: "file.txt", Verdict: "ALLOW"},
	}

	diff := CompareTraces("a", traceA, "b", traceB)

	assert.False(t, diff.Identical)
	assert.Equal(t, 1, diff.MatchCount)
	assert.Equal(t, 0, diff.DivergentCount)
	assert.Equal(t, 1, diff.OnlyInA)
	assert.Equal(t, 0, diff.OnlyInB)
}

func TestCompareTraces_OnlyInB(t *testing.T) {
	traceA := []TraceEntry{
		{Action: "read", Resource: "file.txt", Verdict: "ALLOW"},
	}
	traceB := []TraceEntry{
		{Action: "read", Resource: "file.txt", Verdict: "ALLOW"},
		{Action: "write", Resource: "db.users", Verdict: "DENY"},
	}

	diff := CompareTraces("a", traceA, "b", traceB)

	assert.False(t, diff.Identical)
	assert.Equal(t, 1, diff.MatchCount)
	assert.Equal(t, 0, diff.DivergentCount)
	assert.Equal(t, 0, diff.OnlyInA)
	assert.Equal(t, 1, diff.OnlyInB)
}

func TestCompareTraces_EmptyTraces(t *testing.T) {
	t.Run("both empty", func(t *testing.T) {
		diff := CompareTraces("a", nil, "b", nil)

		assert.True(t, diff.Identical)
		assert.Equal(t, 0, diff.TotalA)
		assert.Equal(t, 0, diff.TotalB)
		assert.Equal(t, 0, diff.MatchCount)
		assert.Equal(t, 0, diff.DivergentCount)
	})

	t.Run("A empty", func(t *testing.T) {
		traceB := []TraceEntry{
			{Action: "read", Resource: "file.txt", Verdict: "ALLOW"},
		}

		diff := CompareTraces("a", nil, "b", traceB)

		assert.False(t, diff.Identical)
		assert.Equal(t, 0, diff.TotalA)
		assert.Equal(t, 1, diff.TotalB)
		assert.Equal(t, 0, diff.OnlyInA)
		assert.Equal(t, 1, diff.OnlyInB)
	})

	t.Run("B empty", func(t *testing.T) {
		traceA := []TraceEntry{
			{Action: "read", Resource: "file.txt", Verdict: "ALLOW"},
		}

		diff := CompareTraces("a", traceA, "b", nil)

		assert.False(t, diff.Identical)
		assert.Equal(t, 1, diff.TotalA)
		assert.Equal(t, 0, diff.TotalB)
		assert.Equal(t, 1, diff.OnlyInA)
		assert.Equal(t, 0, diff.OnlyInB)
	})
}

func TestCompareTraces_SingleEntry(t *testing.T) {
	traceA := []TraceEntry{
		{Action: "read", Resource: "file.txt", Verdict: "ALLOW"},
	}
	traceB := []TraceEntry{
		{Action: "read", Resource: "file.txt", Verdict: "ALLOW"},
	}

	diff := CompareTraces("a", traceA, "b", traceB)

	assert.True(t, diff.Identical)
	assert.Equal(t, 1, diff.MatchCount)
	assert.Equal(t, 0, diff.DivergentCount)
}

func TestCompareTraces_CompletelyDisjoint(t *testing.T) {
	traceA := []TraceEntry{
		{Action: "read", Resource: "file_a.txt", Verdict: "ALLOW"},
	}
	traceB := []TraceEntry{
		{Action: "write", Resource: "file_b.txt", Verdict: "DENY"},
	}

	diff := CompareTraces("a", traceA, "b", traceB)

	assert.False(t, diff.Identical)
	assert.Equal(t, 0, diff.MatchCount)
	assert.Equal(t, 0, diff.DivergentCount)
	assert.Equal(t, 1, diff.OnlyInA)
	assert.Equal(t, 1, diff.OnlyInB)
}

func TestCompareTraces_MultipleDivergences(t *testing.T) {
	traceA := []TraceEntry{
		{Action: "read", Resource: "file.txt", Verdict: "ALLOW"},
		{Action: "write", Resource: "db.users", Verdict: "DENY"},
		{Action: "execute", Resource: "cmd.deploy", Verdict: "ALLOW"},
	}
	traceB := []TraceEntry{
		{Action: "read", Resource: "file.txt", Verdict: "DENY"},
		{Action: "write", Resource: "db.users", Verdict: "ALLOW"},
		{Action: "execute", Resource: "cmd.deploy", Verdict: "ALLOW"},
	}

	diff := CompareTraces("a", traceA, "b", traceB)

	assert.False(t, diff.Identical)
	assert.Equal(t, 1, diff.MatchCount)
	assert.Equal(t, 2, diff.DivergentCount)
	assert.Len(t, diff.Divergences, 2)
}

func TestCompareTraces_SameActionDifferentResources(t *testing.T) {
	traceA := []TraceEntry{
		{Action: "read", Resource: "file_a.txt", Verdict: "ALLOW"},
		{Action: "read", Resource: "file_b.txt", Verdict: "DENY"},
	}
	traceB := []TraceEntry{
		{Action: "read", Resource: "file_a.txt", Verdict: "ALLOW"},
		{Action: "read", Resource: "file_b.txt", Verdict: "DENY"},
	}

	diff := CompareTraces("a", traceA, "b", traceB)

	assert.True(t, diff.Identical)
	assert.Equal(t, 2, diff.MatchCount)
}
