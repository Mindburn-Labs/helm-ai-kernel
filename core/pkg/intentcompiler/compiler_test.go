package intentcompiler_test

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/intent"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/intentcompiler"
)

var fixedTime = time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedTime }

func TestCompile_SingleStep(t *testing.T) {
	c := intentcompiler.NewCompiler().WithClock(fixedClock)

	result, err := c.Compile(&intentcompiler.CompileRequest{
		RawSteps: []string{"Read the config file"},
		PlanName: "read-config",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan == nil {
		t.Fatal("expected plan")
	}
	if result.Plan.DAG == nil {
		t.Fatal("expected DAG")
	}
	if len(result.Plan.DAG.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(result.Plan.DAG.Nodes))
	}
	node := result.Plan.DAG.Nodes[0]
	if node.EffectType != "READ" {
		t.Fatalf("expected READ effect, got %s", node.EffectType)
	}
	if node.RequestedBackend == "" {
		t.Fatal("expected backend assigned")
	}
	if node.RequestedProfile == "" {
		t.Fatal("expected profile assigned")
	}
}

func TestCompile_BuildAndDeploy_Decomposition(t *testing.T) {
	c := intentcompiler.NewCompiler().WithClock(fixedClock)

	result, err := c.Compile(&intentcompiler.CompileRequest{
		RawSteps: []string{"Build and deploy the user service"},
	})
	if err != nil {
		t.Fatal(err)
	}

	dag := result.Plan.DAG
	if len(dag.Nodes) != 2 {
		t.Fatalf("expected 2 nodes (build + deploy), got %d", len(dag.Nodes))
	}
	if len(dag.Edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(dag.Edges))
	}
	if dag.Edges[0].Type != "requires" {
		t.Fatalf("expected requires edge, got %s", dag.Edges[0].Type)
	}

	// Entry point should be the build step (no incoming edges).
	if len(dag.EntryPoints) != 1 {
		t.Fatalf("expected 1 entry point, got %d", len(dag.EntryPoints))
	}
	// Exit point should be the deploy step (no outgoing edges).
	if len(dag.ExitPoints) != 1 {
		t.Fatalf("expected 1 exit point, got %d", len(dag.ExitPoints))
	}
	if dag.EntryPoints[0] == dag.ExitPoints[0] {
		t.Fatal("entry and exit points should differ")
	}
}

func TestCompile_MultipleSteps(t *testing.T) {
	c := intentcompiler.NewCompiler().WithClock(fixedClock)

	result, err := c.Compile(&intentcompiler.CompileRequest{
		RawSteps: []string{
			"Read config",
			"Write output",
			"Send notification via API",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 3 independent steps, no edges between them.
	if len(result.Plan.DAG.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(result.Plan.DAG.Nodes))
	}
	if len(result.Plan.DAG.Edges) != 0 {
		t.Fatalf("expected 0 edges for independent steps, got %d", len(result.Plan.DAG.Edges))
	}
	if len(result.Plan.DAG.EntryPoints) != 3 {
		t.Fatalf("expected 3 entry points, got %d", len(result.Plan.DAG.EntryPoints))
	}
}

func TestCompile_ProfileAssignment(t *testing.T) {
	c := intentcompiler.NewCompiler().WithClock(fixedClock)

	// "Read" → E1 → native
	result, err := c.Compile(&intentcompiler.CompileRequest{
		RawSteps: []string{"Read the file"},
	})
	if err != nil {
		t.Fatal(err)
	}
	node := result.Plan.DAG.Nodes[0]
	// READ isn't in the named catalog, so defaults to E3 → docker.
	// This is correct fail-closed behavior.
	if node.RequestedBackend != "docker" {
		t.Fatalf("expected docker for unknown effect, got %s", node.RequestedBackend)
	}
}

func TestCompile_ConstraintPropagation(t *testing.T) {
	deadline := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	c := intentcompiler.NewCompiler().WithClock(fixedClock)

	result, err := c.Compile(&intentcompiler.CompileRequest{
		RawSteps: []string{"Execute migration"},
		Ticket: &intent.IntentTicket{
			Constraints: intent.IntentConstraints{
				Risk: &intent.RiskConstraint{
					Level:           "low",
					RequireApproval: []string{"INFRA_DESTROY"},
				},
				Timeline: &intent.TimelineConstraint{
					Deadline: &deadline,
				},
				Prohibitions: []string{"delete production data"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Policy constraints should be propagated.
	pc := result.Plan.PolicyConstraints
	if pc == nil {
		t.Fatal("expected policy constraints")
	}
	if len(pc.RequiredApprovals) != 1 || pc.RequiredApprovals[0] != "INFRA_DESTROY" {
		t.Fatalf("expected required approval for INFRA_DESTROY, got %v", pc.RequiredApprovals)
	}
	if pc.TimeoutSeconds <= 0 {
		t.Fatal("expected positive timeout from deadline")
	}

	// Truth annotation should have prohibition assumption.
	truth := result.Plan.Truth
	if truth == nil {
		t.Fatal("expected truth annotation")
	}
	foundProhibition := false
	for _, a := range truth.Assumptions {
		if a == "Prohibited: delete production data" {
			foundProhibition = true
		}
	}
	if !foundProhibition {
		t.Fatalf("expected prohibition in assumptions, got %v", truth.Assumptions)
	}
}

func TestCompile_Hash_Deterministic(t *testing.T) {
	c := intentcompiler.NewCompiler().WithClock(fixedClock)

	r1, _ := c.Compile(&intentcompiler.CompileRequest{
		RawSteps: []string{"Read file"},
		PlanName: "test",
	})
	r2, _ := c.Compile(&intentcompiler.CompileRequest{
		RawSteps: []string{"Read file"},
		PlanName: "test",
	})

	if r1.Plan.Hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if r1.Plan.Hash != r2.Plan.Hash {
		t.Fatalf("hash not deterministic: %s != %s", r1.Plan.Hash, r2.Plan.Hash)
	}
}

func TestCompile_EmptySteps(t *testing.T) {
	c := intentcompiler.NewCompiler()
	_, err := c.Compile(&intentcompiler.CompileRequest{})
	if err == nil {
		t.Fatal("expected error for empty steps")
	}
}

func TestCompile_EffectClassification(t *testing.T) {
	tests := []struct {
		raw        string
		wantEffect string
	}{
		{"Read the config", "READ"},
		{"Fetch user data", "READ"},
		{"Write output file", "WRITE"},
		{"Create new record", "WRITE"},
		{"Delete the old data", "INFRA_DESTROY"},
		{"Deploy to production", "SOFTWARE_PUBLISH"},
		{"Run the tests", "EXECUTE"},
		{"Call the external API", "NETWORK"},
	}

	for _, tt := range tests {
		c := intentcompiler.NewCompiler().WithClock(fixedClock)
		result, err := c.Compile(&intentcompiler.CompileRequest{
			RawSteps: []string{tt.raw},
		})
		if err != nil {
			t.Fatalf("compile %q: %v", tt.raw, err)
		}
		got := result.Plan.DAG.Nodes[0].EffectType
		if got != tt.wantEffect {
			t.Errorf("classify %q: got %s, want %s", tt.raw, got, tt.wantEffect)
		}
	}
}

// ──────────────────────────────────────────────────────────────
// Validator tests
// ──────────────────────────────────────────────────────────────

func TestTopologicalSort_Linear(t *testing.T) {
	dag := &contracts.DAG{
		Nodes: []contracts.PlanStep{
			{ID: "a"},
			{ID: "b"},
			{ID: "c"},
		},
		Edges: []contracts.Edge{
			{From: "a", To: "b", Type: "requires"},
			{From: "b", To: "c", Type: "requires"},
		},
	}

	sorted, err := intentcompiler.TopologicalSort(dag)
	if err != nil {
		t.Fatal(err)
	}
	if len(sorted) != 3 {
		t.Fatalf("expected 3, got %d", len(sorted))
	}
	if sorted[0] != "a" || sorted[1] != "b" || sorted[2] != "c" {
		t.Fatalf("expected [a,b,c], got %v", sorted)
	}
}

func TestTopologicalSort_Diamond(t *testing.T) {
	dag := &contracts.DAG{
		Nodes: []contracts.PlanStep{
			{ID: "a"},
			{ID: "b"},
			{ID: "c"},
			{ID: "d"},
		},
		Edges: []contracts.Edge{
			{From: "a", To: "b"},
			{From: "a", To: "c"},
			{From: "b", To: "d"},
			{From: "c", To: "d"},
		},
	}

	sorted, err := intentcompiler.TopologicalSort(dag)
	if err != nil {
		t.Fatal(err)
	}
	if len(sorted) != 4 {
		t.Fatalf("expected 4, got %d", len(sorted))
	}
	if sorted[0] != "a" {
		t.Fatalf("expected a first, got %s", sorted[0])
	}
	if sorted[3] != "d" {
		t.Fatalf("expected d last, got %s", sorted[3])
	}
}

func TestTopologicalSort_Cycle(t *testing.T) {
	dag := &contracts.DAG{
		Nodes: []contracts.PlanStep{
			{ID: "a"},
			{ID: "b"},
			{ID: "c"},
		},
		Edges: []contracts.Edge{
			{From: "a", To: "b"},
			{From: "b", To: "c"},
			{From: "c", To: "a"}, // cycle
		},
	}

	_, err := intentcompiler.TopologicalSort(dag)
	if err == nil {
		t.Fatal("expected cycle error")
	}
}

func TestTopologicalSort_Independent(t *testing.T) {
	dag := &contracts.DAG{
		Nodes: []contracts.PlanStep{
			{ID: "a"},
			{ID: "b"},
			{ID: "c"},
		},
		Edges: nil,
	}

	sorted, err := intentcompiler.TopologicalSort(dag)
	if err != nil {
		t.Fatal(err)
	}
	if len(sorted) != 3 {
		t.Fatalf("expected 3, got %d", len(sorted))
	}
}

func TestValidator_CycleDetection(t *testing.T) {
	v := intentcompiler.NewGraphValidator(nil)
	plan := &contracts.PlanSpec{
		DAG: &contracts.DAG{
			Nodes: []contracts.PlanStep{
				{ID: "a", EffectType: "EXECUTE"},
				{ID: "b", EffectType: "EXECUTE"},
			},
			Edges: []contracts.Edge{
				{From: "a", To: "b"},
				{From: "b", To: "a"},
			},
		},
	}

	errs := v.Validate(plan)
	hasCycleErr := false
	for _, e := range errs {
		if e.Error() == "DAG contains a cycle" {
			hasCycleErr = true
		}
	}
	if !hasCycleErr {
		t.Fatal("expected cycle error in validation")
	}
}

func TestValidator_DuplicateNodeIDs(t *testing.T) {
	v := intentcompiler.NewGraphValidator(nil)
	plan := &contracts.PlanSpec{
		DAG: &contracts.DAG{
			Nodes: []contracts.PlanStep{
				{ID: "a", EffectType: "EXECUTE"},
				{ID: "a", EffectType: "WRITE"},
			},
		},
	}

	errs := v.Validate(plan)
	if len(errs) == 0 {
		t.Fatal("expected duplicate ID error")
	}
}

func TestValidator_NilDAG(t *testing.T) {
	v := intentcompiler.NewGraphValidator(nil)
	errs := v.Validate(&contracts.PlanSpec{})
	if len(errs) == 0 {
		t.Fatal("expected error for nil DAG")
	}
}

// ──────────────────────────────────────────────────────────────
// Profiler tests
// ──────────────────────────────────────────────────────────────

func TestProfiler_E4Effect(t *testing.T) {
	p := intentcompiler.NewSandboxProfiler()
	step := &contracts.PlanStep{EffectType: "INFRA_DESTROY"}
	backend, profile := p.AssignProfile(step)
	if backend != "docker" {
		t.Fatalf("expected docker for E4, got %s", backend)
	}
	if profile != "net-limited" {
		t.Fatalf("expected net-limited for E4, got %s", profile)
	}
}

func TestProfiler_E1Effect(t *testing.T) {
	p := intentcompiler.NewSandboxProfiler()
	step := &contracts.PlanStep{EffectType: "AGENT_IDENTITY_ISOLATION"}
	backend, profile := p.AssignProfile(step)
	if backend != "native" {
		t.Fatalf("expected native for E1, got %s", backend)
	}
	if profile != "read-only" {
		t.Fatalf("expected read-only for E1, got %s", profile)
	}
}

func TestProfiler_E2Effect(t *testing.T) {
	p := intentcompiler.NewSandboxProfiler()
	step := &contracts.PlanStep{EffectType: "CLOUD_COMPUTE_BUDGET"}
	backend, profile := p.AssignProfile(step)
	if backend != "wasi" {
		t.Fatalf("expected wasi for E2, got %s", backend)
	}
	if profile != "workspace-write" {
		t.Fatalf("expected workspace-write for E2, got %s", profile)
	}
}

func TestProfiler_UnknownEffect_FailClosed(t *testing.T) {
	p := intentcompiler.NewSandboxProfiler()
	step := &contracts.PlanStep{EffectType: "SOME_UNKNOWN_EFFECT"}
	backend, profile := p.AssignProfile(step)
	if backend != "docker" {
		t.Fatalf("expected docker for unknown effect (fail-closed), got %s", backend)
	}
	if profile != "net-limited" {
		t.Fatalf("expected net-limited for unknown (fail-closed), got %s", profile)
	}
}
