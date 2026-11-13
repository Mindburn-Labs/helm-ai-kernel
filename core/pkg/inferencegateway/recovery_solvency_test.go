package inferencegateway

import "testing"

func TestSettlementExcludesItsOwnHoldBeforeCheckingFunds(t *testing.T) {
	for _, tc := range []struct {
		name       string
		own, other int64
		allowed    bool
	}{
		{"unfunded own hold", 100, 0, false},
		{"other hold remains reserved", 40, 30, false},
		{"funded own hold", 40, 10, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *EngineConfig) { c.PlatformFeeBps = 0; c.CostCap = CostCapDebitActual })
			first, err := h.engine.Quote(h.env, h.req("recovered-first", "gpt-6-sol", 10, 10))
			if err != nil {
				t.Fatal(err)
			}
			second, err := h.engine.Quote(h.env, h.req("recovered-second", "gpt-6-sol", 10, 10))
			if err != nil {
				t.Fatal(err)
			}
			h.ledger.account.BalanceCents = 60
			if _, err := h.engine.RestorePendingDispatch(h.env, first.Quote, h.now, tc.own); err != nil {
				t.Fatal(err)
			}
			if tc.other != 0 {
				if _, err := h.engine.RestorePendingDispatch(h.env, second.Quote, h.now, tc.other); err != nil {
					t.Fatal(err)
				}
			}
			_, err = h.engine.Settle(first.Quote, "provider-recovered", tc.own, 10, 10)
			if (err == nil) != tc.allowed {
				t.Fatalf("settlement error %v, allowed %t", err, tc.allowed)
			}
			want := int64(60)
			if tc.allowed {
				want -= tc.own
			}
			if got := h.ledger.BalanceCents(); got != want {
				t.Fatalf("balance %d, want %d", got, want)
			}
			if !tc.allowed && h.ledger.account.HoldCents != tc.own+tc.other {
				t.Fatal("refusal discarded a recovery hold")
			}
		})
	}
}
