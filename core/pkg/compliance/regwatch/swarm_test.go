package regwatch

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

func TestNewSwarm(t *testing.T) {
	g := jkg.NewGraph()
	s := NewSwarm(nil, g)

	require.NotNil(t, s)
	require.NotNil(t, s.config)
	require.NotNil(t, s.metrics)
	require.False(t, s.IsRunning())
}

func TestDefaultSwarmConfig(t *testing.T) {
	c := DefaultSwarmConfig()

	require.Equal(t, 15*time.Minute, c.PollInterval)
	require.Equal(t, 10, c.MaxConcurrency)
	require.Equal(t, 3, c.RetryAttempts)
	require.NotEmpty(t, c.EnabledSources)
}

func TestRegisterAdapter(t *testing.T) {
	g := jkg.NewGraph()
	s := NewSwarm(nil, g)

	adapter := NewTestAdapter(SourceEURLex, jkg.JurisdictionEU)
	err := s.RegisterAdapter(adapter)
	require.NoError(t, err)

	agents := s.GetAgents()
	require.Len(t, agents, 1)
	require.Equal(t, AgentSourceMonitor, agents[0].Type)
}

func TestRegisterAdapterNil(t *testing.T) {
	g := jkg.NewGraph()
	s := NewSwarm(nil, g)

	err := s.RegisterAdapter(nil)
	require.Error(t, err)
}

func TestSwarmStartStop(t *testing.T) {
	g := jkg.NewGraph()
	config := &SwarmConfig{
		PollInterval:     1 * time.Hour, // Long interval to avoid polling
		MaxConcurrency:   5,
		RetryAttempts:    1,
		RetryDelay:       10 * time.Millisecond,
		ChangeBufferSize: 10,
	}
	s := NewSwarm(config, g)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := s.Start(ctx)
	require.NoError(t, err)
	require.True(t, s.IsRunning())

	// Double start should error
	err = s.Start(ctx)
	require.Error(t, err)

	s.Stop()
	require.False(t, s.IsRunning())
}

func TestSwarmPollNow(t *testing.T) {
	g := jkg.NewGraph()
	s := NewSwarm(nil, g)

	// Register test adapter with changes
	adapter := NewTestAdapter(SourceEURLex, jkg.JurisdictionEU)
	adapter.SetChanges([]*RegChange{
		{
			SourceType:       SourceEURLex,
			ChangeType:       ChangeNew,
			JurisdictionCode: jkg.JurisdictionEU,
			Title:            "New MiCA Amendment",
			PublishedAt:      time.Now(),
		},
	})
	_ = s.RegisterAdapter(adapter)

	ctx := context.Background()
	s.PollNow(ctx)

	// Check metrics
	metrics := s.GetMetrics()
	require.Equal(t, int64(1), metrics.TotalPolls)
	require.Equal(t, int64(1), metrics.TotalChanges)
}

func TestSwarmChangesChannel(t *testing.T) {
	g := jkg.NewGraph()
	s := NewSwarm(nil, g)

	adapter := NewTestAdapter(SourceFinCEN, jkg.JurisdictionUS)
	adapter.SetChanges([]*RegChange{
		{
			SourceType:       SourceFinCEN,
			ChangeType:       ChangeGuidance,
			JurisdictionCode: jkg.JurisdictionUS,
			Title:            "FinCEN Advisory",
			PublishedAt:      time.Now(),
		},
	})
	_ = s.RegisterAdapter(adapter)

	ctx := context.Background()
	s.PollNow(ctx)

	// Should receive change on channel
	select {
	case change := <-s.Changes():
		require.Equal(t, SourceFinCEN, change.SourceType)
		require.Equal(t, "FinCEN Advisory", change.Title)
		require.NotEmpty(t, change.ChangeID)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected change on channel")
	}
}

func TestSwarmUnhealthyAdapter(t *testing.T) {
	g := jkg.NewGraph()
	s := NewSwarm(nil, g)

	adapter := NewTestAdapter(SourceFCA, jkg.JurisdictionGB)
	adapter.SetHealthy(false)
	_ = s.RegisterAdapter(adapter)

	ctx := context.Background()
	s.PollNow(ctx)

	metrics := s.GetMetrics()
	require.Equal(t, 1, metrics.UnhealthyAgents)
	require.Equal(t, 0, metrics.HealthyAgents)
}

func TestSwarmAdapterError(t *testing.T) {
	g := jkg.NewGraph()
	config := &SwarmConfig{
		PollInterval:     1 * time.Hour,
		MaxConcurrency:   5,
		RetryAttempts:    0, // No retries
		RetryDelay:       1 * time.Millisecond,
		ChangeBufferSize: 10,
	}
	s := NewSwarm(config, g)

	adapter := NewTestAdapter(SourceESMA, jkg.JurisdictionEU)
	adapter.SetFetchError(fmt.Errorf("network error"))
	_ = s.RegisterAdapter(adapter)

	ctx := context.Background()
	s.PollNow(ctx)

	agents := s.GetAgents()
	require.Len(t, agents, 1)
	require.False(t, agents[0].IsHealthy)
	require.Equal(t, "network error", agents[0].LastError)
}

func TestSwarmMultipleAdapters(t *testing.T) {
	g := jkg.NewGraph()
	s := NewSwarm(nil, g)

	_ = s.RegisterAdapter(NewTestAdapter(SourceEURLex, jkg.JurisdictionEU))
	_ = s.RegisterAdapter(NewTestAdapter(SourceFinCEN, jkg.JurisdictionUS))
	_ = s.RegisterAdapter(NewTestAdapter(SourceFCA, jkg.JurisdictionGB))

	agents := s.GetAgents()
	require.Len(t, agents, 3)
}

func TestSwarmMetrics(t *testing.T) {
	g := jkg.NewGraph()
	s := NewSwarm(nil, g)

	euAdapter := NewTestAdapter(SourceEURLex, jkg.JurisdictionEU)
	euAdapter.SetChanges([]*RegChange{
		{SourceType: SourceEURLex, ChangeType: ChangeNew, Title: "Change 1", PublishedAt: time.Now()},
		{SourceType: SourceEURLex, ChangeType: ChangeAmendment, Title: "Change 2", PublishedAt: time.Now()},
	})

	usAdapter := NewTestAdapter(SourceFinCEN, jkg.JurisdictionUS)
	usAdapter.SetChanges([]*RegChange{
		{SourceType: SourceFinCEN, ChangeType: ChangeGuidance, Title: "Change 3", PublishedAt: time.Now()},
	})

	_ = s.RegisterAdapter(euAdapter)
	_ = s.RegisterAdapter(usAdapter)

	ctx := context.Background()
	s.PollNow(ctx)

	metrics := s.GetMetrics()
	require.Equal(t, int64(2), metrics.TotalPolls)
	require.Equal(t, int64(3), metrics.TotalChanges)
	require.Equal(t, int64(2), metrics.ChangesBySource[SourceEURLex])
	require.Equal(t, int64(1), metrics.ChangesBySource[SourceFinCEN])
	require.Equal(t, int64(1), metrics.ChangesByType[ChangeNew])
	require.Equal(t, int64(1), metrics.ChangesByType[ChangeAmendment])
	require.Equal(t, int64(1), metrics.ChangesByType[ChangeGuidance])
}

func TestEURLexAdapter(t *testing.T) {
	adapter := NewEURLexAdapter([]string{"MiCA"})

	require.Equal(t, SourceEURLex, adapter.Type())
	require.Equal(t, jkg.JurisdictionEU, adapter.Jurisdiction())
	require.Equal(t, jkg.RegulatorESMA, adapter.Regulator())
	require.True(t, adapter.IsHealthy(context.Background()))

	changes, err := adapter.FetchChanges(context.Background(), time.Now())
	require.NoError(t, err)
	require.NotNil(t, changes)
}

func TestFinCENAdapter(t *testing.T) {
	adapter := NewFinCENAdapter()

	require.Equal(t, SourceFinCEN, adapter.Type())
	require.Equal(t, jkg.JurisdictionUS, adapter.Jurisdiction())
	require.True(t, adapter.IsHealthy(context.Background()))
}

func TestFCAAdapter(t *testing.T) {
	adapter := NewFCAAdapter()

	require.Equal(t, SourceFCA, adapter.Type())
	require.Equal(t, jkg.JurisdictionGB, adapter.Jurisdiction())
	require.True(t, adapter.IsHealthy(context.Background()))
}

func TestESMAAdapter(t *testing.T) {
	adapter := NewESMAAdapter()

	require.Equal(t, SourceESMA, adapter.Type())
	require.Equal(t, jkg.JurisdictionEU, adapter.Jurisdiction())
	require.True(t, adapter.IsHealthy(context.Background()))
}

func TestCreateDefaultAdapters(t *testing.T) {
	adapters := CreateDefaultAdapters()
	require.Len(t, adapters, 4)
}

func TestCreateSwarmWithDefaults(t *testing.T) {
	g := jkg.NewGraph()
	swarm, err := CreateSwarmWithDefaults(g)

	require.NoError(t, err)
	require.NotNil(t, swarm)

	agents := swarm.GetAgents()
	require.Len(t, agents, 4)
}

func TestChangeIDGeneration(t *testing.T) {
	change := &RegChange{
		SourceType:       SourceEURLex,
		JurisdictionCode: jkg.JurisdictionEU,
		Title:            "Test Regulation",
		SourceURL:        "https://example.com/reg",
		PublishedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	id1 := generateChangeID(change)
	id2 := generateChangeID(change)

	require.Equal(t, id1, id2) // Deterministic
	require.Len(t, id1, 16)

	// Different change = different ID
	change.Title = "Different Title"
	id3 := generateChangeID(change)
	require.NotEqual(t, id1, id3)
}
