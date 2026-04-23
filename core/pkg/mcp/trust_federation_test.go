package mcp

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFederatedReport_AffectsScore(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	// Record a success to establish a local score.
	scorer.RecordSuccess("srv1", "tool_a")
	tsLocal, ok := scorer.GetScore("srv1", "tool_a")
	require.True(t, ok)
	localScore := tsLocal.Score // 800 (base=500, success_rate=300, age=0)

	// Record a federated report with a very low score.
	scorer.RecordFederatedReport(FederatedTrustReport{
		PeerID:     "peer-1",
		ServerID:   "srv1",
		ToolName:   "tool_a",
		Score:      100,
		ReportedAt: now,
	})

	tsFed, ok := scorer.GetScore("srv1", "tool_a")
	require.True(t, ok)

	// Blended: 0.7 * 800 + 0.3 * 100 = 560 + 30 = 590
	assert.Less(t, tsFed.Score, localScore,
		"federated low score should decrease final score")
	assert.Equal(t, 590, tsFed.Score)
}

func TestFederatedReport_MultiplePeers(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	scorer.RecordSuccess("srv1", "tool_a")

	// Two federated reports.
	scorer.RecordFederatedReport(FederatedTrustReport{
		PeerID: "peer-1", ServerID: "srv1", ToolName: "tool_a",
		Score: 200, ReportedAt: now,
	})
	scorer.RecordFederatedReport(FederatedTrustReport{
		PeerID: "peer-2", ServerID: "srv1", ToolName: "tool_a",
		Score: 400, ReportedAt: now,
	})

	ts, ok := scorer.GetScore("srv1", "tool_a")
	require.True(t, ok)

	// Local = 800, federated avg = (200+400)/2 = 300
	// Blended: 0.7 * 800 + 0.3 * 300 = 560 + 90 = 650
	assert.Equal(t, 650, ts.Score)
}

func TestFederatedReport_NoLocalScore(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	// Record federated report before any local observation.
	scorer.RecordFederatedReport(FederatedTrustReport{
		PeerID: "peer-1", ServerID: "srv1", ToolName: "tool_a",
		Score: 100, ReportedAt: now,
	})

	// No local score yet — tool should not appear.
	_, ok := scorer.GetScore("srv1", "tool_a")
	assert.False(t, ok, "federated-only report should not create a local score entry")

	// Now record a local event — federated should be factored in.
	scorer.RecordSuccess("srv1", "tool_a")
	ts, ok := scorer.GetScore("srv1", "tool_a")
	require.True(t, ok)

	// Local = 800 (1 success, 0 failures), federated avg = 100
	// Blended: 0.7 * 800 + 0.3 * 100 = 560 + 30 = 590
	assert.Equal(t, 590, ts.Score)
}

func TestFederatedReport_HighFederatedBoostsScore(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	// Mixed local record: 1 success, 1 failure.
	scorer.RecordSuccess("srv1", "tool_a")
	scorer.RecordFailure("srv1", "tool_a")
	tsLocal, _ := scorer.GetScore("srv1", "tool_a")
	localScore := tsLocal.Score // 550

	// Federated peers report high trust.
	scorer.RecordFederatedReport(FederatedTrustReport{
		PeerID: "peer-1", ServerID: "srv1", ToolName: "tool_a",
		Score: 1000, ReportedAt: now,
	})

	tsFed, _ := scorer.GetScore("srv1", "tool_a")

	// Blended: 0.7 * 550 + 0.3 * 1000 = 385 + 300 = 685
	assert.Greater(t, tsFed.Score, localScore,
		"high federated scores should increase final score")
	assert.Equal(t, 685, tsFed.Score)
}

func TestFederatedReport_IndependentTools(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	scorer.RecordSuccess("srv1", "tool_a")
	scorer.RecordSuccess("srv1", "tool_b")

	// Federated report only for tool_a.
	scorer.RecordFederatedReport(FederatedTrustReport{
		PeerID: "peer-1", ServerID: "srv1", ToolName: "tool_a",
		Score: 0, ReportedAt: now,
	})

	tsA, _ := scorer.GetScore("srv1", "tool_a")
	tsB, _ := scorer.GetScore("srv1", "tool_b")

	assert.NotEqual(t, tsA.Score, tsB.Score,
		"federated report on tool_a should not affect tool_b")
	assert.Equal(t, 800, tsB.Score, "tool_b should remain at pure local score")
}

func TestFederatedReport_ReportFields(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 30, 0, 0, time.UTC)

	report := FederatedTrustReport{
		PeerID:     "peer-alpha",
		ServerID:   "mcp-server-1",
		ToolName:   "file_read",
		Score:      750,
		ReportedAt: now,
	}

	assert.Equal(t, "peer-alpha", report.PeerID)
	assert.Equal(t, "mcp-server-1", report.ServerID)
	assert.Equal(t, "file_read", report.ToolName)
	assert.Equal(t, 750, report.Score)
	assert.Equal(t, now, report.ReportedAt)
}

func TestFederatedReport_ConcurrentAccess(t *testing.T) {
	scorer := NewTrustScorer()
	scorer.RecordSuccess("srv1", "tool_a")

	var wg sync.WaitGroup

	// Concurrent federated reports.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			scorer.RecordFederatedReport(FederatedTrustReport{
				PeerID:     "peer",
				ServerID:   "srv1",
				ToolName:   "tool_a",
				Score:      500,
				ReportedAt: time.Now(),
			})
		}(i)
	}

	// Concurrent reads.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scorer.GetScore("srv1", "tool_a")
		}()
	}

	wg.Wait()

	ts, ok := scorer.GetScore("srv1", "tool_a")
	require.True(t, ok)
	assert.Greater(t, ts.Score, 0, "score should be positive after concurrent access")
}

func TestFederatedReport_WithLocalFailures(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	scorer := NewTrustScorer(WithTrustClock(fixedClock(now)))

	// All failures locally.
	for i := 0; i < 10; i++ {
		scorer.RecordFailure("srv1", "tool_a")
	}

	tsLocal, _ := scorer.GetScore("srv1", "tool_a")
	// Local: base=500, success=0, age=0, error=-200 = 300
	assert.Equal(t, 300, tsLocal.Score)

	// Federated peers say it is fine.
	scorer.RecordFederatedReport(FederatedTrustReport{
		PeerID: "peer-1", ServerID: "srv1", ToolName: "tool_a",
		Score: 900, ReportedAt: now,
	})

	tsFed, _ := scorer.GetScore("srv1", "tool_a")
	// Blended: 0.7 * 300 + 0.3 * 900 = 210 + 270 = 480
	assert.Equal(t, 480, tsFed.Score)
}
