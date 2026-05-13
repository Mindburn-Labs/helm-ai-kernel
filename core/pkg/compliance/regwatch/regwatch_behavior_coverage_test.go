package regwatch

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/compliance/jkg"
)

// ── SwarmConfig ─────────────────────────────────────────────────

func TestComprehensive_DefaultSwarmConfig(t *testing.T) {
	cfg := DefaultSwarmConfig()
	if cfg.PollInterval != 15*time.Minute {
		t.Errorf("expected 15m poll interval, got %v", cfg.PollInterval)
	}
	if cfg.MaxConcurrency != 10 {
		t.Errorf("expected max concurrency 10, got %d", cfg.MaxConcurrency)
	}
	if cfg.RetryAttempts != 3 {
		t.Errorf("expected 3 retry attempts, got %d", cfg.RetryAttempts)
	}
}

// ── Swarm ───────────────────────────────────────────────────────

func TestComprehensive_NewSwarm_NilConfig(t *testing.T) {
	g := jkg.NewGraph()
	s := NewSwarm(nil, g)
	if s.config == nil {
		t.Error("should use default config when nil")
	}
}

func TestComprehensive_RegisterAdapter(t *testing.T) {
	g := jkg.NewGraph()
	s := NewSwarm(nil, g)
	adapter := NewTestAdapter(SourceEURLex, "EU")
	if err := s.RegisterAdapter(adapter); err != nil {
		t.Fatalf("RegisterAdapter: %v", err)
	}
	agents := s.GetAgents()
	if len(agents) != 1 {
		t.Errorf("expected 1 agent, got %d", len(agents))
	}
}

func TestComprehensive_RegisterNilAdapter(t *testing.T) {
	g := jkg.NewGraph()
	s := NewSwarm(nil, g)
	if err := s.RegisterAdapter(nil); err == nil {
		t.Error("should reject nil adapter")
	}
}

func TestComprehensive_StartStop(t *testing.T) {
	cfg := &SwarmConfig{
		PollInterval:     100 * time.Millisecond,
		MaxConcurrency:   1,
		ChangeBufferSize: 10,
	}
	g := jkg.NewGraph()
	s := NewSwarm(cfg, g)
	adapter := NewTestAdapter(SourceEURLex, "EU")
	_ = s.RegisterAdapter(adapter)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !s.IsRunning() {
		t.Error("swarm should be running")
	}
	s.Stop()
	if s.IsRunning() {
		t.Error("swarm should be stopped")
	}
}

func TestComprehensive_DoubleStartFails(t *testing.T) {
	g := jkg.NewGraph()
	s := NewSwarm(nil, g)
	ctx := context.Background()
	_ = s.Start(ctx)
	defer s.Stop()
	if err := s.Start(ctx); err == nil {
		t.Error("should reject double start")
	}
}

func TestComprehensive_PollNowWithChanges(t *testing.T) {
	cfg := &SwarmConfig{
		PollInterval:     1 * time.Hour,
		MaxConcurrency:   5,
		ChangeBufferSize: 10,
		RetryAttempts:    0,
	}
	g := jkg.NewGraph()
	s := NewSwarm(cfg, g)
	adapter := NewTestAdapter(SourceFinCEN, "US")
	adapter.SetChanges([]*RegChange{{
		Title:            "New Rule",
		SourceType:       SourceFinCEN,
		ChangeType:       ChangeNew,
		JurisdictionCode: "US",
		PublishedAt:      time.Now(),
	}})
	_ = s.RegisterAdapter(adapter)
	s.PollNow(context.Background())

	select {
	case ch := <-s.Changes():
		if ch.Title != "New Rule" {
			t.Errorf("unexpected title: %s", ch.Title)
		}
	default:
		t.Error("expected a change to be published")
	}
}

func TestComprehensive_UnhealthyAdapterSkipped(t *testing.T) {
	cfg := &SwarmConfig{
		PollInterval:     1 * time.Hour,
		MaxConcurrency:   5,
		ChangeBufferSize: 10,
	}
	g := jkg.NewGraph()
	s := NewSwarm(cfg, g)
	adapter := NewTestAdapter(SourceFCA, "GB")
	adapter.SetHealthy(false)
	_ = s.RegisterAdapter(adapter)
	s.PollNow(context.Background())

	agents := s.GetAgents()
	for _, a := range agents {
		if a.IsHealthy {
			t.Error("unhealthy adapter should mark agent unhealthy")
		}
	}
}

func TestComprehensive_MetricsUpdated(t *testing.T) {
	cfg := &SwarmConfig{
		PollInterval:     1 * time.Hour,
		MaxConcurrency:   5,
		ChangeBufferSize: 10,
		RetryAttempts:    0,
	}
	g := jkg.NewGraph()
	s := NewSwarm(cfg, g)
	adapter := NewTestAdapter(SourceESMA, "EU")
	adapter.SetChanges([]*RegChange{{
		Title:       "X",
		SourceType:  SourceESMA,
		ChangeType:  ChangeAmendment,
		PublishedAt: time.Now(),
	}})
	_ = s.RegisterAdapter(adapter)
	s.PollNow(context.Background())

	m := s.GetMetrics()
	if m.TotalPolls < 1 {
		t.Error("TotalPolls should be >= 1")
	}
	if m.TotalChanges < 1 {
		t.Error("TotalChanges should be >= 1")
	}
}

// ── RegChange ───────────────────────────────────────────────────

func TestComprehensive_GenerateChangeID_Deterministic(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := &RegChange{
		SourceType:       SourceEURLex,
		JurisdictionCode: "EU",
		Title:            "Test",
		SourceURL:        "https://example.com",
		PublishedAt:      ts,
	}
	id1 := generateChangeID(c)
	id2 := generateChangeID(c)
	if id1 != id2 {
		t.Error("change ID should be deterministic")
	}
}

func TestComprehensive_ChangeID_Length(t *testing.T) {
	c := &RegChange{
		SourceType:  SourceSEC,
		Title:       "SEC Rule",
		PublishedAt: time.Now(),
	}
	id := generateChangeID(c)
	if len(id) != 16 {
		t.Errorf("expected 16-char ID, got %d", len(id))
	}
}

// ── SourceType constants ────────────────────────────────────────

func TestComprehensive_SourceTypes_Defined(t *testing.T) {
	types := []SourceType{SourceEURLex, SourceFinCEN, SourceFCA, SourceSEC, SourceESMA}
	for _, st := range types {
		if st == "" {
			t.Error("source type should not be empty")
		}
	}
}

func TestComprehensive_ChangeTypes_Defined(t *testing.T) {
	types := []ChangeType{ChangeNew, ChangeAmendment, ChangeGuidance, ChangeRepeal, ChangeDeadline}
	for _, ct := range types {
		if ct == "" {
			t.Error("change type should not be empty")
		}
	}
}

// ── Extended source types ───────────────────────────────────────

func TestComprehensive_ExtendedSourceTypes(t *testing.T) {
	extended := []SourceType{
		SourceNISTAIRMF, SourceEUAIAct, SourceOFAC, SourceFATF,
		SourceNISTCSF, SourceNIS2, SourceDORA, SourceCISAKEV,
	}
	for _, st := range extended {
		if st == "" {
			t.Errorf("extended source type should not be empty")
		}
	}
}

func TestComprehensive_SwarmChangesChannel(t *testing.T) {
	g := jkg.NewGraph()
	cfg := &SwarmConfig{PollInterval: time.Hour, MaxConcurrency: 1, ChangeBufferSize: 5}
	s := NewSwarm(cfg, g)
	ch := s.Changes()
	if ch == nil {
		t.Error("Changes channel should not be nil")
	}
}
