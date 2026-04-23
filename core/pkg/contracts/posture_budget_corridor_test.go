package contracts

import (
	"testing"
)

func TestPostureRanking(t *testing.T) {
	tests := []struct {
		from        Posture
		to          Posture
		canEscalate bool
	}{
		{PostureObserve, PostureDraft, true},
		{PostureObserve, PostureTransact, true},
		{PostureObserve, PostureSovereign, true},
		{PostureDraft, PostureTransact, true},
		{PostureDraft, PostureSovereign, true},
		{PostureTransact, PostureSovereign, true},
		// Cannot escalate to same or lower
		{PostureObserve, PostureObserve, false},
		{PostureDraft, PostureObserve, false},
		{PostureTransact, PostureDraft, false},
		{PostureSovereign, PostureTransact, false},
		{PostureSovereign, PostureSovereign, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.from)+"->"+string(tt.to), func(t *testing.T) {
			got := tt.from.CanEscalateTo(tt.to)
			if got != tt.canEscalate {
				t.Errorf("CanEscalateTo(%s, %s) = %v, want %v", tt.from, tt.to, got, tt.canEscalate)
			}
		})
	}
}

func TestAllPosturesOrdering(t *testing.T) {
	postures := AllPostures()
	if len(postures) != 4 {
		t.Fatalf("expected 4 postures, got %d", len(postures))
	}
	expected := []Posture{PostureObserve, PostureDraft, PostureTransact, PostureSovereign}
	for i, p := range postures {
		if p != expected[i] {
			t.Errorf("posture[%d] = %s, want %s", i, p, expected[i])
		}
	}
}

func TestBudgetExhaustion(t *testing.T) {
	b := &Budget{
		MaxTokens:    1000,
		MaxCostCents: 500,
		MaxEffects:   10,
	}

	if b.Exhausted() {
		t.Error("fresh budget should not be exhausted")
	}

	b.ConsumedTokens = 1000
	if !b.Exhausted() {
		t.Error("budget at token ceiling should be exhausted")
	}

	b.ConsumedTokens = 0
	b.ConsumedCostCents = 500
	if !b.Exhausted() {
		t.Error("budget at cost ceiling should be exhausted")
	}

	b.ConsumedCostCents = 0
	b.ConsumedEffects = 10
	if !b.Exhausted() {
		t.Error("budget at effect ceiling should be exhausted")
	}
}

func TestBudgetRemainingTokens(t *testing.T) {
	b := &Budget{MaxTokens: 1000, ConsumedTokens: 250}
	if r := b.RemainingTokens(); r != 750 {
		t.Errorf("remaining = %d, want 750", r)
	}

	b.ConsumedTokens = 1500 // over budget
	if r := b.RemainingTokens(); r != 0 {
		t.Errorf("over-budget remaining = %d, want 0", r)
	}
}
