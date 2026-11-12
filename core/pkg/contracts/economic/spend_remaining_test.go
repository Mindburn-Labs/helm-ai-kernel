package economic

import (
	"math"
	"testing"
)

// TestRemainingCentsDoesNotWrap (helm-tracker#313 r1, F12): used and reserved
// cents near the int64 limit leave nothing, and never wrap to a large
// remaining amount; an envelope whose used plus reserved would wrap does not
// validate.
func TestRemainingCentsDoesNotWrap(t *testing.T) {
	for name, test := range map[string]struct {
		max, used, reserved int64
		want                int64
	}{
		"used saturated, some reserved": {1000, math.MaxInt64, 2000, 0},
		"reserved saturated":            {1000, 10, math.MaxInt64, 0},
		"both at the limit":             {math.MaxInt64, math.MaxInt64, math.MaxInt64, 0},
		"max at the limit, some used":   {math.MaxInt64, 1, 1, math.MaxInt64 - 2},
		"within the limit":              {1000, 300, 200, 500},
	} {
		env := &AgentSpendEnvelope{MaxAmountCents: test.max, UsedAmountCents: test.used, ReservedAmountCents: test.reserved}
		if got := env.RemainingCents(); got != test.want {
			t.Errorf("%s: remaining = %d, want %d", name, got, test.want)
		}
	}
	env := spendAuthorityTestEnvelope()
	env.UsedAmountCents = math.MaxInt64
	env.ReservedAmountCents = 1
	if err := env.Validate(); err == nil {
		t.Fatal("an envelope whose used plus reserved wraps validated")
	}
}
