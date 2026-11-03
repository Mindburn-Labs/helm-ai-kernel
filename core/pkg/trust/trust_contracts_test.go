package trust

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestFinal_TrustTierForScorePristine(t *testing.T) {
	if TierForScore(950) != TierPristine {
		t.Fatal("950 should be PRISTINE")
	}
}

func TestFinal_TrustTierForScoreTrusted(t *testing.T) {
	if TierForScore(750) != TierTrusted {
		t.Fatal("750 should be TRUSTED")
	}
}

func TestFinal_TrustTierForScoreNeutral(t *testing.T) {
	if TierForScore(500) != TierNeutral {
		t.Fatal("500 should be NEUTRAL")
	}
}

func TestFinal_TrustTierForScoreSuspect(t *testing.T) {
	if TierForScore(300) != TierSuspect {
		t.Fatal("300 should be SUSPECT")
	}
}

func TestFinal_TrustTierForScoreHostile(t *testing.T) {
	if TierForScore(50) != TierHostile {
		t.Fatal("50 should be HOSTILE")
	}
}

func TestFinal_TrustTierBoundary900(t *testing.T) {
	if TierForScore(900) != TierPristine {
		t.Fatal("900 is PRISTINE boundary")
	}
}

func TestFinal_TrustTierBoundary700(t *testing.T) {
	if TierForScore(700) != TierTrusted {
		t.Fatal("700 is TRUSTED boundary")
	}
}

func TestFinal_TrustTierBoundary400(t *testing.T) {
	if TierForScore(400) != TierNeutral {
		t.Fatal("400 is NEUTRAL boundary")
	}
}

func TestFinal_TrustTierBoundary200(t *testing.T) {
	if TierForScore(200) != TierSuspect {
		t.Fatal("200 is SUSPECT boundary")
	}
}

func TestFinal_TrustTierZero(t *testing.T) {
	if TierForScore(0) != TierHostile {
		t.Fatal("0 should be HOSTILE")
	}
}

func TestFinal_ScoreEventTypeConstants(t *testing.T) {
	types := []ScoreEventType{EventPolicyComply, EventPolicyViolate, EventRateLimitHit, EventThreatDetected, EventDelegationValid, EventDelegationAbuse, EventEgressBlocked, EventManualBoost, EventManualPenalty}
	seen := make(map[ScoreEventType]bool)
	for _, et := range types {
		if et == "" {
			t.Fatal("event type must not be empty")
		}
		if seen[et] {
			t.Fatalf("duplicate: %s", et)
		}
		seen[et] = true
	}
}

func TestFinal_DefaultDeltasNonEmpty(t *testing.T) {
	if len(DefaultDeltas) == 0 {
		t.Fatal("DefaultDeltas must not be empty")
	}
}

func TestFinal_DefaultDeltasGoodPositive(t *testing.T) {
	if DefaultDeltas[EventPolicyComply] <= 0 {
		t.Fatal("POLICY_COMPLY should have positive delta")
	}
}

func TestFinal_DefaultDeltasBadNegative(t *testing.T) {
	if DefaultDeltas[EventPolicyViolate] >= 0 {
		t.Fatal("POLICY_VIOLATE should have negative delta")
	}
}

func TestFinal_BehavioralTrustScoreNormalized(t *testing.T) {
	bts := &BehavioralTrustScore{Score: 500}
	if bts.Normalized() != 0.5 {
		t.Fatalf("want 0.5, got %f", bts.Normalized())
	}
}

func TestFinal_BehavioralTrustScoreJSON(t *testing.T) {
	bts := BehavioralTrustScore{AgentID: "a1", Score: 800, Tier: TierTrusted}
	data, _ := json.Marshal(bts)
	var bts2 BehavioralTrustScore
	json.Unmarshal(data, &bts2)
	if bts2.AgentID != "a1" || bts2.Score != 800 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_PackRefJSON(t *testing.T) {
	pr := PackRef{Name: "org.example/my-pack", Version: "1.0.0"}
	data, _ := json.Marshal(pr)
	var pr2 PackRef
	json.Unmarshal(data, &pr2)
	if pr2.Name != "org.example/my-pack" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ScoreEventJSON(t *testing.T) {
	se := ScoreEvent{EventType: EventPolicyComply, Delta: 2, Reason: "complied"}
	data, _ := json.Marshal(se)
	var se2 ScoreEvent
	json.Unmarshal(data, &se2)
	if se2.Delta != 2 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ConcurrentTierForScore(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(score int) {
			defer wg.Done()
			_ = TierForScore(score * 50)
		}(i)
	}
	wg.Wait()
}

func TestFinal_TrustTierUniqueness(t *testing.T) {
	tiers := []TrustTier{TierPristine, TierTrusted, TierNeutral, TierSuspect, TierHostile}
	seen := make(map[TrustTier]bool)
	for _, tier := range tiers {
		if seen[tier] {
			t.Fatalf("duplicate tier: %s", tier)
		}
		seen[tier] = true
	}
}

func TestFinal_NormalizedBounds(t *testing.T) {
	for _, score := range []int{0, 500, 1000} {
		bts := &BehavioralTrustScore{Score: score}
		n := bts.Normalized()
		if n < 0 || n > 1.0 {
			t.Fatalf("normalized out of range for score %d: %f", score, n)
		}
	}
}
