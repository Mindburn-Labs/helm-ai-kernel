package kernel

import (
	"strings"
	"testing"
)

func TestTaskClassifierClassifyFromDAG(t *testing.T) {
	classifier := DefaultTaskClassifier()
	if classifier.ParallelThreshold != 0.7 || classifier.HybridThreshold != 0.3 ||
		classifier.MaxSequentialDepth != 8 || classifier.MinSubtasks != 3 {
		t.Fatalf("unexpected default thresholds: %+v", classifier)
	}

	empty := classifier.ClassifyFromDAG(nil, nil)
	if empty.Decomposability != 0 || empty.SequentialDepth != 0 {
		t.Fatalf("empty DAG should have zeroed structural properties: %+v", empty)
	}

	independent := classifier.ClassifyFromDAG(
		[]string{"a", "b", "c", "d", "e", "f", "g", "h"},
		map[string][]string{},
	)
	if independent.SequentialDepth != 1 {
		t.Fatalf("expected one-step depth, got %+v", independent)
	}
	assertFloatWithin(t, independent.Decomposability, 1.0, 0.0001)
	assertFloatWithin(t, independent.ParallelizableFraction, 0.875, 0.0001)
	assertFloatWithin(t, independent.ToolDensity, 1.0, 0.0001)
	if independent.EstimatedSubtasks != 8 || independent.ErrorAmplificationRisk <= 0 {
		t.Fatalf("unexpected independent properties: %+v", independent)
	}

	chain := classifier.ClassifyFromDAG(
		[]string{"a", "b", "c"},
		map[string][]string{
			"a": {"b"},
			"b": {"c"},
			"c": {},
		},
	)
	if chain.SequentialDepth != 3 {
		t.Fatalf("expected full chain depth, got %+v", chain)
	}
	assertFloatWithin(t, chain.Decomposability, 1.0/3.0, 0.0001)
	assertFloatWithin(t, chain.ParallelizableFraction, 0, 0.0001)

	overdeep := classifier.ClassifyFromDAG(
		[]string{"a", "x"},
		map[string][]string{
			"a": {"b"},
			"b": {"c"},
			"c": {"d"},
			"d": {},
			"x": {},
		},
	)
	if overdeep.SequentialDepth != 4 {
		t.Fatalf("expected external dependency chain to contribute depth, got %+v", overdeep)
	}
	assertFloatWithin(t, overdeep.ParallelizableFraction, 0, 0.0001)
}

func TestTaskClassifierSelectModeBranches(t *testing.T) {
	classifier := DefaultTaskClassifier()

	cases := []struct {
		name      string
		props     TaskProperties
		wantMode  CoordinationMode
		rationale string
	}{
		{
			name:      "too few subtasks",
			props:     TaskProperties{EstimatedSubtasks: 2, SequentialDepth: 1, ParallelizableFraction: 1},
			wantMode:  ModeWaterfall,
			rationale: "only 2 subtasks",
		},
		{
			name:      "deep sequential chain",
			props:     TaskProperties{EstimatedSubtasks: 9, SequentialDepth: 9, ParallelizableFraction: 1},
			wantMode:  ModeWaterfall,
			rationale: "sequential depth 9 exceeds max 8",
		},
		{
			name:      "high error amplification",
			props:     TaskProperties{EstimatedSubtasks: 4, SequentialDepth: 1, ParallelizableFraction: 1, ErrorAmplificationRisk: 0.31},
			wantMode:  ModeHybrid,
			rationale: "error amplification risk",
		},
		{
			name:      "highly parallel",
			props:     TaskProperties{EstimatedSubtasks: 4, SequentialDepth: 1, ParallelizableFraction: 0.8, ErrorAmplificationRisk: 0.1},
			wantMode:  ModeParallel,
			rationale: "parallelizable fraction exceeds threshold",
		},
		{
			name:      "moderately parallel",
			props:     TaskProperties{EstimatedSubtasks: 4, SequentialDepth: 1, ParallelizableFraction: 0.5, ErrorAmplificationRisk: 0.1},
			wantMode:  ModeHybrid,
			rationale: "between 30% and 70%",
		},
		{
			name:      "mostly sequential",
			props:     TaskProperties{EstimatedSubtasks: 4, SequentialDepth: 1, ParallelizableFraction: 0.1, ErrorAmplificationRisk: 0.1},
			wantMode:  ModeWaterfall,
			rationale: "below 30% threshold",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode, rationale := classifier.SelectMode(tc.props)
			if mode != tc.wantMode {
				t.Fatalf("mode mismatch: got %s want %s; rationale=%s", mode, tc.wantMode, rationale)
			}
			if !strings.Contains(rationale, tc.rationale) {
				t.Fatalf("rationale %q does not contain %q", rationale, tc.rationale)
			}
		})
	}
}

func TestComputeCriticalPathSharedDependencies(t *testing.T) {
	depth := computeCriticalPath(
		[]string{"long", "wide", "short"},
		map[string][]string{
			"long":  {"mid", "leaf"},
			"mid":   {"leaf"},
			"leaf":  {},
			"wide":  {"leaf"},
			"short": {},
		},
	)
	if depth != 3 {
		t.Fatalf("expected longest chain length 3, got %d", depth)
	}
}

func assertFloatWithin(t *testing.T, got, want, tolerance float64) {
	t.Helper()

	diff := got - want
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance {
		t.Fatalf("got %f, want %f within %f", got, want, tolerance)
	}
}
