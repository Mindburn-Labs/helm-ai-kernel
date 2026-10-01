package modelgw

import (
	"math"
	"math/rand"
	"testing"
)

func mustRoute(t testing.TB, id string) *Route {
	t.Helper()
	cfg := testConfig(t, "https://a.test", "https://o.test/v1", "https://r.test/v1")
	for _, r := range cfg.Routes() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no route %s", id)
	return nil
}

func TestQuoteIsTheWorstCaseRoundedUpOnce(t *testing.T) {
	sonnet := mustRoute(t, routeSonnet) // 3 usd per Mtok in, 15 out
	for _, test := range []struct {
		name          string
		bytes, maxOut int64
		cache         bool
		want          int64
	}{
		{"one thousand each way", 1000, 1000, false, 18_000},
		{"nothing to say", 0, 0, false, 0},
		{"a byte rounds up to a whole micro", 1, 0, false, 3},
		{"the sum is rounded, not each term", 1, 1, false, 18}, // 3 + 15 exactly
		{"a cache write may cost more than input", 1_000_000, 0, true, 6_000_000},
		{"no cache marker, no surcharge", 1_000_000, 0, false, 3_000_000},
	} {
		got, err := sonnet.Quote(test.bytes, test.maxOut, test.cache)
		if err != nil || got != test.want {
			t.Errorf("%s: Quote = %d, %v, want %d", test.name, got, err, test.want)
		}
	}
	// A cheap tariff is exact, not rounded down to nothing: 42000 per Mtok.
	cheap := mustRoute(t, routeOR)
	if got, _ := cheap.Quote(1, 0, false); got != 1 {
		t.Fatalf("a single byte on a 0.042 USD/Mtok route quotes %d micros, want 1 (rounded up)", got)
	}
	if got, _ := cheap.Quote(1_000_000, 0, false); got != 42_000 {
		t.Fatalf("a million input bytes on a 0.042 USD/Mtok route quotes %d, want exactly 42000", got)
	}
}

func TestQuoteRefusesOverflowAndNegatives(t *testing.T) {
	sonnet := mustRoute(t, routeSonnet)
	for name, args := range map[string][2]int64{
		"input overflows":   {math.MaxInt64 / 2, 0},
		"output overflows":  {0, math.MaxInt64 / 2},
		"the sum overflows": {math.MaxInt64 / 3_000_000, math.MaxInt64 / 15_000_000}, // each term fits, together they do not
		"negative input":    {-1, 0},
		"negative output":   {0, -1},
	} {
		if got, err := sonnet.Quote(args[0], args[1], false); err == nil {
			t.Errorf("%s: Quote = %d, nil; want a refusal", name, got)
		}
	}
}

func TestCostPricesReportedUsageAtTheTariff(t *testing.T) {
	sonnet := mustRoute(t, routeSonnet)
	got, err := sonnet.Cost(Usage{InputTokens: 100, CacheReadTokens: 1000, CacheWrite5mTokens: 40, CacheWrite1hTokens: 10, OutputTokens: 50})
	// 100*3 + 1000*0.3 + 40*3.75 + 10*6 + 50*15 = 300 + 300 + 150 + 60 + 750 = 1560 micro-per-token units / 1e6 → but prices are per Mtok:
	// (100*3e6 + 1000*3e5 + 40*3.75e6 + 10*6e6 + 50*15e6) / 1e6 = 300+300+150+60+750 = 1560
	if err != nil || got != 1560 {
		t.Fatalf("Cost = %d, %v, want 1560", got, err)
	}
	// Cache prices default to the input price: gpt-6-sol names only cache_read.
	gpt := mustRoute(t, routeGPT)
	if got, _ := gpt.Cost(Usage{CacheWrite5mTokens: 1000}); got != 2000 {
		t.Fatalf("an unpriced cache write costs %d, want the input price 2000", got)
	}
	if _, err := sonnet.Cost(Usage{OutputTokens: -1}); err == nil {
		t.Fatal("a negative usage was priced")
	}
	if _, err := sonnet.Cost(Usage{InputTokens: math.MaxInt64 / 2}); err == nil {
		t.Fatal("a usage that overflows was priced")
	}
}

// The property the ledger rests on: a call that stays within its bound never
// costs more than its quote, so billable never exceeds held.
func TestAnyUsageWithinTheBoundCostsNoMoreThanTheQuote(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, id := range []string{routeOpus, routeSonnet, routeHaiku, routeGPT, routeOR} {
		route := mustRoute(t, id)
		for i := 0; i < 5000; i++ {
			bytes := rng.Int63n(4 << 20)
			maxOut := 1 + rng.Int63n(route.MaxOutputTokens)
			cache := rng.Intn(2) == 0
			quote, err := route.Quote(bytes, maxOut, cache)
			if err != nil {
				t.Fatal(err)
			}
			// Tokens are at most one per byte; the input is split across the
			// counters, and cache writes only when the request may write.
			tokens := rng.Int63n(bytes + 1)
			var u Usage
			u.OutputTokens = rng.Int63n(maxOut + 1)
			cr := rng.Int63n(tokens + 1)
			u.CacheReadTokens = cr
			rest := tokens - cr
			if cache {
				w5 := rng.Int63n(rest + 1)
				u.CacheWrite5mTokens = w5
				w1 := rng.Int63n(rest - w5 + 1)
				u.CacheWrite1hTokens = w1
				rest -= w5 + w1
			}
			u.InputTokens = rest
			cost, err := route.Cost(u)
			if err != nil {
				t.Fatal(err)
			}
			// A cache read is dearer than input only if the tariff says so,
			// which the illustrative tariffs never do.
			if cost > quote {
				t.Fatalf("%s: cost %d exceeds quote %d for %d bytes, max %d, cache %v, usage %+v", id, cost, quote, bytes, maxOut, cache, u)
			}
		}
	}
}
