package regwatch

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/compliance/jkg"
)

func TestAllDefaultAdaptersFetchHealthAndToggle(t *testing.T) {
	ctx := context.Background()
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, adapter := range CreateDefaultAdaptersAll() {
		t.Run(string(adapter.Type()), func(t *testing.T) {
			changes, err := adapter.FetchChanges(ctx, since)
			if err != nil {
				t.Fatalf("FetchChanges: %v", err)
			}
			if changes == nil {
				t.Fatal("FetchChanges returned nil slice")
			}
			if !adapter.IsHealthy(ctx) {
				t.Fatal("adapter should start healthy")
			}

			setter, ok := adapter.(interface{ SetHealthy(bool) })
			if !ok {
				return
			}
			setter.SetHealthy(false)
			if adapter.IsHealthy(ctx) {
				t.Fatal("adapter stayed healthy after SetHealthy(false)")
			}
			setter.SetHealthy(true)
			if !adapter.IsHealthy(ctx) {
				t.Fatal("adapter stayed unhealthy after SetHealthy(true)")
			}
		})
	}
}

func TestCFTCAdapterSeedDataAndTrackingAreas(t *testing.T) {
	customAreas := []string{"prediction_markets", "ai_agents"}
	adapter := NewCFTCAdapter(customAreas)
	if got := adapter.TrackingAreas(); len(got) != len(customAreas) {
		t.Fatalf("TrackingAreas len = %d, want %d", len(got), len(customAreas))
	}
	for i, area := range customAreas {
		if adapter.TrackingAreas()[i] != area {
			t.Fatalf("TrackingAreas[%d] = %q, want %q", i, adapter.TrackingAreas()[i], area)
		}
	}

	changes, err := adapter.FetchChanges(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("FetchChanges: %v", err)
	}
	if len(changes) != 6 {
		t.Fatalf("CFTC seed changes = %d, want 6", len(changes))
	}
	for _, change := range changes {
		if change.SourceType != SourceCFTC {
			t.Fatalf("SourceType = %s, want %s", change.SourceType, SourceCFTC)
		}
		if change.RegulatorID == "" || change.Framework == "" || change.Metadata == nil {
			t.Fatalf("incomplete CFTC change: %#v", change)
		}
	}

	defaulted := NewCFTCAdapter(nil)
	if len(defaulted.TrackingAreas()) != 4 {
		t.Fatalf("default TrackingAreas len = %d, want 4", len(defaulted.TrackingAreas()))
	}
}

func TestEURLexUnknownFrameworkProducesNoChange(t *testing.T) {
	adapter := NewEURLexAdapter([]string{"unknown-framework"})
	changes, err := adapter.FetchChanges(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("FetchChanges: %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("unknown framework changes = %d, want 0", len(changes))
	}
}

func TestEURLexAMLDAndDORAFrameworks(t *testing.T) {
	adapter := NewEURLexAdapter([]string{"AMLD", "DORA"})
	changes, err := adapter.FetchChanges(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("FetchChanges: %v", err)
	}
	if len(changes) != 2 {
		t.Fatalf("framework changes = %d, want 2", len(changes))
	}
	want := map[string]bool{"AMLD": false, "DORA": false}
	for _, change := range changes {
		if _, ok := want[change.Framework]; ok {
			want[change.Framework] = true
		}
	}
	for framework, seen := range want {
		if !seen {
			t.Fatalf("missing framework %s in %#v", framework, changes)
		}
	}
}

func TestSwarmIdleStopPollLoopAndFullChangeChannel(t *testing.T) {
	idle := NewSwarm(&SwarmConfig{
		PollInterval:     time.Hour,
		MaxConcurrency:   1,
		ChangeBufferSize: 1,
	}, jkg.NewGraph())
	idle.Stop()

	tickerSwarm := NewSwarm(&SwarmConfig{
		PollInterval:     time.Millisecond,
		MaxConcurrency:   1,
		ChangeBufferSize: 1,
	}, jkg.NewGraph())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tickerSwarm.pollLoop(ctx)
		close(done)
	}()
	time.Sleep(5 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pollLoop did not exit after context cancellation")
	}

	full := NewSwarm(&SwarmConfig{
		PollInterval:     time.Hour,
		MaxConcurrency:   1,
		ChangeBufferSize: 1,
		RetryAttempts:    0,
	}, jkg.NewGraph())
	adapter := NewTestAdapter(SourceFinCEN, "US")
	adapter.SetChanges([]*RegChange{
		{Title: "first", SourceType: SourceFinCEN, ChangeType: ChangeNew, PublishedAt: time.Now()},
		{Title: "second", SourceType: SourceFinCEN, ChangeType: ChangeGuidance, PublishedAt: time.Now()},
	})
	if err := full.RegisterAdapter(adapter); err != nil {
		t.Fatalf("RegisterAdapter: %v", err)
	}
	full.PollNow(context.Background())
	if full.GetMetrics().TotalChanges != 2 {
		t.Fatalf("TotalChanges = %d, want 2", full.GetMetrics().TotalChanges)
	}
	select {
	case <-full.Changes():
	default:
		t.Fatal("expected one buffered change")
	}
}
