package trust

import (
	"testing"
)

func TestComputePackTrustScore(t *testing.T) {
	metrics := PackMetrics{
		AttestationCompleteness: 1.0, // 30% -> 0.3
		ReplayDeterminism:       0.8, // 30% -> 0.24
		InjectionResilience:     1.0, // 20% -> 0.2
		SLOAdherence:            0.5, // 20% -> 0.1
	}

	// Expected: 0.3 + 0.24 + 0.2 + 0.1 = 0.84
	expected := 0.84

	score := ComputePackTrustScore(metrics)

	if score.PackScore != expected {
		t.Errorf("expected score %.2f, got %.2f", expected, score.PackScore)
	}

	if score.OverallScore != expected {
		t.Errorf("expected overall score %.2f, got %.2f", expected, score.OverallScore)
	}

	// Verify badge level
	badge := GetBadgeLevel(score.OverallScore)
	if badge != BadgeSilver { // 0.84 is Silver (>0.70, <=0.85)
		t.Errorf("expected BadgeSilver, got %s", badge)
	}
}

func TestComputePackTrustScore_Platinum(t *testing.T) {
	metrics := PackMetrics{
		AttestationCompleteness: 1.0,
		ReplayDeterminism:       1.0,
		InjectionResilience:     1.0,
		SLOAdherence:            1.0,
	}

	score := ComputePackTrustScore(metrics)

	if score.OverallScore != 1.0 {
		t.Errorf("expected 1.0, got %.2f", score.OverallScore)
	}

	badge := GetBadgeLevel(score.OverallScore)
	if badge != BadgePlatinum {
		t.Errorf("expected BadgePlatinum, got %s", badge)
	}
}

func TestTrustScore_StructUpdates(t *testing.T) {
	score := &TrustScore{
		PackScore: 0.9,
	}
	if score.PackScore != 0.9 {
		t.Error("PackScore field not working")
	}
}
