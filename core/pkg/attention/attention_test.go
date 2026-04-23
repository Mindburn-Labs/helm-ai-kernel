package attention

import (
	"context"
	"math"
	"testing"
	"time"
)

const floatTolerance = 1e-9

func approxEqual(a, b float64) bool {
	return math.Abs(a-b) < floatTolerance
}

// --- Store CRUD ---

func TestInMemoryWatchlistStore_AddAndList(t *testing.T) {
	store := NewInMemoryWatchlistStore()
	ctx := context.Background()

	w := &Watch{
		WatchID:    "w-1",
		Type:       WatchTypePerson,
		EntityID:   "person-alice",
		EntityName: "Alice",
		Priority:   80,
		TopicTags:  []string{"finance", "compliance"},
		OwnerID:    "principal-1",
		CreatedAt:  time.Now(),
	}

	if err := store.Add(ctx, w); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	watches, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(watches) != 1 {
		t.Fatalf("expected 1 watch, got %d", len(watches))
	}
	if watches[0].WatchID != "w-1" {
		t.Errorf("expected watch_id w-1, got %s", watches[0].WatchID)
	}
}

func TestInMemoryWatchlistStore_AddDuplicate(t *testing.T) {
	store := NewInMemoryWatchlistStore()
	ctx := context.Background()

	w := &Watch{WatchID: "w-1", Type: WatchTypePerson, EntityID: "person-1"}
	if err := store.Add(ctx, w); err != nil {
		t.Fatalf("first Add failed: %v", err)
	}
	if err := store.Add(ctx, w); err == nil {
		t.Error("expected error on duplicate Add")
	}
}

func TestInMemoryWatchlistStore_Remove(t *testing.T) {
	store := NewInMemoryWatchlistStore()
	ctx := context.Background()

	w := &Watch{WatchID: "w-1", Type: WatchTypePerson, EntityID: "person-1"}
	if err := store.Add(ctx, w); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	if err := store.Remove(ctx, "w-1"); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	watches, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(watches) != 0 {
		t.Errorf("expected 0 watches after remove, got %d", len(watches))
	}
}

func TestInMemoryWatchlistStore_RemoveNotFound(t *testing.T) {
	store := NewInMemoryWatchlistStore()
	ctx := context.Background()

	if err := store.Remove(ctx, "nonexistent"); err == nil {
		t.Error("expected error when removing nonexistent watch")
	}
}

func TestInMemoryWatchlistStore_ByEntity(t *testing.T) {
	store := NewInMemoryWatchlistStore()
	ctx := context.Background()

	_ = store.Add(ctx, &Watch{WatchID: "w-1", Type: WatchTypePerson, EntityID: "person-alice"})
	_ = store.Add(ctx, &Watch{WatchID: "w-2", Type: WatchTypeAccount, EntityID: "acct-001"})
	_ = store.Add(ctx, &Watch{WatchID: "w-3", Type: WatchTypePerson, EntityID: "person-bob"})

	matches, err := store.ByEntity(ctx, "PERSON", "person-alice")
	if err != nil {
		t.Fatalf("ByEntity failed: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].WatchID != "w-1" {
		t.Errorf("expected w-1, got %s", matches[0].WatchID)
	}
}

// --- WatchType ---

func TestWatchType_IsValid(t *testing.T) {
	if !WatchTypePerson.IsValid() {
		t.Error("PERSON should be valid")
	}
	if !WatchTypeProgram.IsValid() {
		t.Error("PROGRAM should be valid")
	}
	if WatchType("UNKNOWN").IsValid() {
		t.Error("UNKNOWN should not be valid")
	}
}

// --- Score Computation ---

func TestScoreComputer_Sensitivities(t *testing.T) {
	sc := NewScoreComputer()

	tests := []struct {
		sensitivity string
		priority    int
		wantScore   float64
	}{
		{"PUBLIC", 100, 0.2},
		{"INTERNAL", 100, 0.4},
		{"CONFIDENTIAL", 100, 0.7},
		{"RESTRICTED", 100, 1.0},
		{"RESTRICTED", 50, 0.5},
		{"RESTRICTED", 0, 0.0},
		{"UNKNOWN_LEVEL", 100, 0.2}, // defaults to PUBLIC weight
	}

	for _, tt := range tests {
		w := &Watch{Priority: tt.priority}
		got := sc.Compute("EMAIL", tt.sensitivity, w)
		if !approxEqual(got, tt.wantScore) {
			t.Errorf("Compute(EMAIL, %s, priority=%d) = %.10f, want %.2f",
				tt.sensitivity, tt.priority, got, tt.wantScore)
		}
	}
}

func TestScoreComputer_ClampsPriority(t *testing.T) {
	sc := NewScoreComputer()

	// Priority above 100 should be clamped to 1.0
	w := &Watch{Priority: 200}
	got := sc.Compute("EMAIL", "RESTRICTED", w)
	if got != 1.0 {
		t.Errorf("expected clamped score 1.0, got %.2f", got)
	}

	// Negative priority should clamp to 0
	w2 := &Watch{Priority: -10}
	got2 := sc.Compute("EMAIL", "RESTRICTED", w2)
	if got2 != 0.0 {
		t.Errorf("expected clamped score 0.0, got %.2f", got2)
	}
}

// --- Cluster Building ---

func TestClusterBuilder_GroupsByEntityAndTopic(t *testing.T) {
	cb := NewClusterBuilder()

	cb.AddSignal("sig-1", "entity-a", "finance", 0.5)
	cb.AddSignal("sig-2", "entity-a", "finance", 0.8)
	cb.AddSignal("sig-3", "entity-a", "legal", 0.3)
	cb.AddSignal("sig-4", "entity-b", "finance", 0.6)

	clusters := cb.Build()

	if len(clusters) != 3 {
		t.Fatalf("expected 3 clusters, got %d", len(clusters))
	}

	// Find the (entity-a, finance) cluster
	var found bool
	for _, c := range clusters {
		if c.EntityID == "entity-a" && c.Topic == "finance" {
			found = true
			if c.Count != 2 {
				t.Errorf("expected 2 signals in cluster, got %d", c.Count)
			}
			if len(c.SignalIDs) != 2 {
				t.Errorf("expected 2 signal IDs, got %d", len(c.SignalIDs))
			}
			if c.AggScore != 0.8 {
				t.Errorf("expected agg score 0.8, got %.2f", c.AggScore)
			}
		}
	}
	if !found {
		t.Error("cluster (entity-a, finance) not found")
	}
}

func TestClusterBuilder_EmptyBuild(t *testing.T) {
	cb := NewClusterBuilder()
	clusters := cb.Build()
	if len(clusters) != 0 {
		t.Errorf("expected 0 clusters from empty builder, got %d", len(clusters))
	}
}

// --- Router ---

func TestDefaultRouter_RouteMatchesWatches(t *testing.T) {
	store := NewInMemoryWatchlistStore()
	router := NewDefaultRouter(store)
	ctx := context.Background()

	w := &Watch{
		WatchID:  "w-1",
		Type:     WatchTypePerson,
		EntityID: "person-alice",
		Priority: 80,
	}
	if err := router.AddWatch(ctx, w); err != nil {
		t.Fatalf("AddWatch failed: %v", err)
	}

	scores, err := router.Route(ctx, "sig-001", "EMAIL", "CONFIDENTIAL", "person-alice", "PERSON")
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}
	if len(scores) != 1 {
		t.Fatalf("expected 1 score, got %d", len(scores))
	}

	as := scores[0]
	if as.SignalID != "sig-001" {
		t.Errorf("expected signal_id sig-001, got %s", as.SignalID)
	}
	if as.WatchID != "w-1" {
		t.Errorf("expected watch_id w-1, got %s", as.WatchID)
	}
	// CONFIDENTIAL (0.7) * priority 80/100 = 0.56
	if !approxEqual(as.Score, 0.56) {
		t.Errorf("expected score ~0.56, got %.10f", as.Score)
	}
	if !as.ShouldRoute {
		t.Error("expected ShouldRoute to be true")
	}
	if as.EscalationHint != nil {
		t.Error("expected no escalation hint for score 0.56")
	}
}

func TestDefaultRouter_RouteNoMatch(t *testing.T) {
	store := NewInMemoryWatchlistStore()
	router := NewDefaultRouter(store)
	ctx := context.Background()

	_ = router.AddWatch(ctx, &Watch{
		WatchID:  "w-1",
		Type:     WatchTypePerson,
		EntityID: "person-alice",
		Priority: 80,
	})

	scores, err := router.Route(ctx, "sig-001", "EMAIL", "INTERNAL", "person-bob", "PERSON")
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}
	if len(scores) != 0 {
		t.Errorf("expected 0 scores for non-matching entity, got %d", len(scores))
	}
}

func TestDefaultRouter_RemoveWatch(t *testing.T) {
	store := NewInMemoryWatchlistStore()
	router := NewDefaultRouter(store)
	ctx := context.Background()

	_ = router.AddWatch(ctx, &Watch{WatchID: "w-1", Type: WatchTypePerson, EntityID: "person-alice", Priority: 50})

	if err := router.RemoveWatch(ctx, "w-1"); err != nil {
		t.Fatalf("RemoveWatch failed: %v", err)
	}

	scores, err := router.Route(ctx, "sig-001", "EMAIL", "INTERNAL", "person-alice", "PERSON")
	if err != nil {
		t.Fatalf("Route after remove failed: %v", err)
	}
	if len(scores) != 0 {
		t.Errorf("expected 0 scores after removing watch, got %d", len(scores))
	}
}

// --- Escalation ---

func TestShouldEscalate_BelowThreshold(t *testing.T) {
	hint := ShouldEscalate(0.5)
	if hint != nil {
		t.Error("expected nil hint for score 0.5")
	}
}

func TestShouldEscalate_AtThreshold(t *testing.T) {
	hint := ShouldEscalate(0.8)
	if hint != nil {
		t.Error("expected nil hint for score exactly at threshold (0.8)")
	}
}

func TestShouldEscalate_AboveThreshold(t *testing.T) {
	hint := ShouldEscalate(0.85)
	if hint == nil {
		t.Fatal("expected escalation hint for score 0.85")
	}
	if hint.Urgency != UrgencyHigh {
		t.Errorf("expected urgency %s, got %s", UrgencyHigh, hint.Urgency)
	}
	if hint.TargetRole != "operator" {
		t.Errorf("expected target_role operator, got %s", hint.TargetRole)
	}
}

func TestShouldEscalate_Immediate(t *testing.T) {
	hint := ShouldEscalate(0.96)
	if hint == nil {
		t.Fatal("expected escalation hint for score 0.96")
	}
	if hint.Urgency != UrgencyImmediate {
		t.Errorf("expected urgency %s, got %s", UrgencyImmediate, hint.Urgency)
	}
}

// --- Router with escalation ---

func TestDefaultRouter_RouteWithEscalation(t *testing.T) {
	store := NewInMemoryWatchlistStore()
	router := NewDefaultRouter(store)
	ctx := context.Background()

	// RESTRICTED (1.0) * priority 100/100 = 1.0 -> should escalate
	_ = router.AddWatch(ctx, &Watch{
		WatchID:  "w-1",
		Type:     WatchTypeIncident,
		EntityID: "incident-critical",
		Priority: 100,
	})

	scores, err := router.Route(ctx, "sig-001", "SYSTEM_ALERT", "RESTRICTED", "incident-critical", "INCIDENT")
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}
	if len(scores) != 1 {
		t.Fatalf("expected 1 score, got %d", len(scores))
	}

	as := scores[0]
	if as.Score != 1.0 {
		t.Errorf("expected score 1.0, got %.4f", as.Score)
	}
	if as.EscalationHint == nil {
		t.Fatal("expected escalation hint for score 1.0")
	}
	if as.EscalationHint.Urgency != UrgencyImmediate {
		t.Errorf("expected urgency %s, got %s", UrgencyImmediate, as.EscalationHint.Urgency)
	}
}

// --- ProgramState ---

func TestProgramState_Constants(t *testing.T) {
	states := []string{ProgramStatusActive, ProgramStatusPaused, ProgramStatusCompleted, ProgramStatusFailed}
	expected := []string{"ACTIVE", "PAUSED", "COMPLETED", "FAILED"}
	for i, s := range states {
		if s != expected[i] {
			t.Errorf("expected %s, got %s", expected[i], s)
		}
	}
}
