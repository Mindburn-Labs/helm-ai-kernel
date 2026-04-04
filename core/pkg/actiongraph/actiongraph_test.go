package actiongraph

import (
	"context"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Risk class mapping
// ---------------------------------------------------------------------------

func TestRiskClassToEffectClass(t *testing.T) {
	tests := []struct {
		rc   ActionRiskClass
		want string
	}{
		{RiskClassR0, "E0"},
		{RiskClassR1, "E1"},
		{RiskClassR2, "E2"},
		{RiskClassR3, "E4"},
		{ActionRiskClass("UNKNOWN"), "E3"},
		{ActionRiskClass(""), "E3"},
	}
	for _, tt := range tests {
		got := RiskClassToEffectClass(tt.rc)
		if got != tt.want {
			t.Errorf("RiskClassToEffectClass(%q) = %q, want %q", tt.rc, got, tt.want)
		}
	}
}

func TestRequiresInboxVisibility(t *testing.T) {
	tests := []struct {
		rc   ActionRiskClass
		want bool
	}{
		{RiskClassR0, false},
		{RiskClassR1, false},
		{RiskClassR2, true},
		{RiskClassR3, true},
	}
	for _, tt := range tests {
		got := RequiresInboxVisibility(tt.rc)
		if got != tt.want {
			t.Errorf("RequiresInboxVisibility(%q) = %v, want %v", tt.rc, got, tt.want)
		}
	}
}

func TestRequiresApprovalCeremony(t *testing.T) {
	tests := []struct {
		rc   ActionRiskClass
		want bool
	}{
		{RiskClassR0, false},
		{RiskClassR1, false},
		{RiskClassR2, false},
		{RiskClassR3, true},
	}
	for _, tt := range tests {
		got := RequiresApprovalCeremony(tt.rc)
		if got != tt.want {
			t.Errorf("RequiresApprovalCeremony(%q) = %v, want %v", tt.rc, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Dependency graph
// ---------------------------------------------------------------------------

func TestDependencyGraph_LinearChain(t *testing.T) {
	g := NewDependencyGraph()
	// A -> B -> C (C depends on B, B depends on A)
	must(t, g.Add(&WorkItem{ItemID: "A"}))
	must(t, g.Add(&WorkItem{ItemID: "B", DependsOn: []string{"A"}}))
	must(t, g.Add(&WorkItem{ItemID: "C", DependsOn: []string{"B"}}))

	order, err := g.TopologicalSort()
	if err != nil {
		t.Fatalf("TopologicalSort: %v", err)
	}

	idx := indexMap(order)
	if idx["A"] >= idx["B"] || idx["B"] >= idx["C"] {
		t.Errorf("wrong order: got %v, want A before B before C", order)
	}
}

func TestDependencyGraph_Diamond(t *testing.T) {
	g := NewDependencyGraph()
	//   A
	//  / \
	// B   C
	//  \ /
	//   D
	must(t, g.Add(&WorkItem{ItemID: "A"}))
	must(t, g.Add(&WorkItem{ItemID: "B", DependsOn: []string{"A"}}))
	must(t, g.Add(&WorkItem{ItemID: "C", DependsOn: []string{"A"}}))
	must(t, g.Add(&WorkItem{ItemID: "D", DependsOn: []string{"B", "C"}}))

	order, err := g.TopologicalSort()
	if err != nil {
		t.Fatalf("TopologicalSort: %v", err)
	}

	idx := indexMap(order)
	if idx["A"] >= idx["B"] {
		t.Errorf("A should come before B, got %v", order)
	}
	if idx["A"] >= idx["C"] {
		t.Errorf("A should come before C, got %v", order)
	}
	if idx["B"] >= idx["D"] {
		t.Errorf("B should come before D, got %v", order)
	}
	if idx["C"] >= idx["D"] {
		t.Errorf("C should come before D, got %v", order)
	}
}

func TestDependencyGraph_CycleDetection(t *testing.T) {
	g := NewDependencyGraph()
	must(t, g.Add(&WorkItem{ItemID: "A", DependsOn: []string{"C"}}))
	must(t, g.Add(&WorkItem{ItemID: "B", DependsOn: []string{"A"}}))
	must(t, g.Add(&WorkItem{ItemID: "C", DependsOn: []string{"B"}}))

	_, err := g.TopologicalSort()
	if err == nil {
		t.Fatal("expected cycle error, got nil")
	}
}

func TestDependencyGraph_DuplicateItem(t *testing.T) {
	g := NewDependencyGraph()
	must(t, g.Add(&WorkItem{ItemID: "A"}))
	if err := g.Add(&WorkItem{ItemID: "A"}); err == nil {
		t.Fatal("expected duplicate error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Action store CRUD
// ---------------------------------------------------------------------------

func TestInMemoryActionStore_CRUD(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryActionStore()

	proposal := &ActionProposal{
		ProposalID:  "p-1",
		Title:       "Test proposal",
		Status:      "PROPOSED",
		RiskClass:   RiskClassR1,
		CreatedAt:   time.Now(),
		ContentHash: "abc123",
	}

	// Create
	if err := store.Create(ctx, proposal); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Duplicate create
	if err := store.Create(ctx, proposal); err == nil {
		t.Fatal("expected duplicate error on second Create")
	}

	// Get
	got, err := store.Get(ctx, "p-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Title != "Test proposal" {
		t.Errorf("Get title = %q, want %q", got.Title, "Test proposal")
	}

	// Get not found
	if _, err := store.Get(ctx, "nonexistent"); err == nil {
		t.Fatal("expected not-found error")
	}

	// ListByStatus
	list, err := store.ListByStatus(ctx, "PROPOSED", 10)
	if err != nil {
		t.Fatalf("ListByStatus: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListByStatus len = %d, want 1", len(list))
	}

	// ListByStatus empty
	list, err = store.ListByStatus(ctx, "COMPLETED", 10)
	if err != nil {
		t.Fatalf("ListByStatus: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("ListByStatus len = %d, want 0", len(list))
	}

	// UpdateStatus
	if err := store.UpdateStatus(ctx, "p-1", "APPROVED"); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	got, _ = store.Get(ctx, "p-1")
	if got.Status != "APPROVED" {
		t.Errorf("status after update = %q, want APPROVED", got.Status)
	}

	// UpdateStatus not found
	if err := store.UpdateStatus(ctx, "nonexistent", "APPROVED"); err == nil {
		t.Fatal("expected not-found error on UpdateStatus")
	}
}

// ---------------------------------------------------------------------------
// Action deduplicator
// ---------------------------------------------------------------------------

func TestActionDeduplicator(t *testing.T) {
	d := NewActionDeduplicator()

	if d.IsDuplicate("hash1") {
		t.Fatal("hash1 should not be duplicate before recording")
	}

	d.Record("hash1")

	if !d.IsDuplicate("hash1") {
		t.Fatal("hash1 should be duplicate after recording")
	}

	if d.IsDuplicate("hash2") {
		t.Fatal("hash2 should not be duplicate")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func indexMap(order []string) map[string]int {
	m := make(map[string]int, len(order))
	for i, id := range order {
		m[id] = i
	}
	return m
}
