package economic

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func exactPriceFixture() *ProviderPriceSnapshot {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	return &ProviderPriceSnapshot{
		SchemaVersion: ProviderPriceSchemaV2,
		ID:            "price-jev", ProviderID: "typesafe", ModelID: "jev-1.13.0", Currency: "USD",
		InputTokenNanoCents: 4200, ProviderTermsProfileID: "reviewed-terms",
		SourceURI: "https://docs.typesafe.ai/models", SourceHash: "sha256:" + strings.Repeat("a", 64),
		CapturedAt: now, EffectiveAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func TestExactProviderPricePreservesJevTariff(t *testing.T) {
	p := exactPriceFixture()
	if err := p.Seal(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ input, exact, reserve int64 }{
		{1, 4200, 1}, {100000, 420000000, 1}, {1000000, 4200000000, 5},
	} {
		exact, err := p.ExactCostNanoCents(c.input, 100)
		if err != nil || exact != c.exact {
			t.Fatalf("exact(%d)=%d, %v; want %d", c.input, exact, err, c.exact)
		}
		reserve, err := p.QuoteCents(c.input, 100)
		if err != nil || reserve != c.reserve {
			t.Fatalf("reserve(%d)=%d, %v; want %d", c.input, reserve, err, c.reserve)
		}
	}
	// An observation may legitimately contain zero billed tokens. It must not
	// become a fabricated minimum provider charge.
	if got, err := p.ExactCostNanoCents(0, 0); err != nil || got != 0 {
		t.Fatalf("zero usage=%d, %v", got, err)
	}
	if p.ContentHash != p.CanonicalDigest() {
		t.Fatal("sealed digest differs")
	}
}

func TestLegacyProviderPriceBytesAndDigestRemainCompatible(t *testing.T) {
	const legacy = `{"id":"legacy-price","provider_id":"typesafe","model_id":"jev-legacy","currency":"USD","input_token_micro_cents":5,"provider_terms_profile_id":"terms","source_hash":"sha256:source","captured_at":"2026-09-29T00:00:00Z","effective_at":"2026-09-29T00:00:00Z","expires_at":"2026-09-29T01:00:00Z","content_hash":""}`
	var p ProviderPriceSnapshot
	if err := json.Unmarshal([]byte(legacy), &p); err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(&p)
	if err != nil || string(got) != legacy {
		t.Fatalf("legacy wire bytes changed: %s %v", got, err)
	}
	if p.CanonicalDigest() != "sha256:397c120e771bbb5b6897d716606e1b685ead0cba107b92eb2b2d7b97b7044497" {
		t.Fatal("legacy price digest changed")
	}
	if got, err := p.QuoteCents(1000000, 0); err != nil || got != 5 {
		t.Fatalf("legacy quote=%d %v", got, err)
	}
	if _, err := p.ExactCostNanoCents(1, 0); err == nil {
		t.Fatal("legacy price silently promoted")
	}
}

func TestExactProviderPriceRejectsMixedUnitsAndOverflow(t *testing.T) {
	for _, mutate := range []func(*ProviderPriceSnapshot){
		func(p *ProviderPriceSnapshot) { p.InputTokenMicroCents = 4 },
		func(p *ProviderPriceSnapshot) { p.RequestCents = 1 },
		func(p *ProviderPriceSnapshot) { p.InputTokenNanoCents = -1 },
		func(p *ProviderPriceSnapshot) { p.SchemaVersion = "future" },
		func(p *ProviderPriceSnapshot) { p.SchemaVersion = "" },
		func(p *ProviderPriceSnapshot) { p.CapturedAt = time.Time{} },
		func(p *ProviderPriceSnapshot) { p.EffectiveAt = time.Time{} },
		func(p *ProviderPriceSnapshot) { p.Currency = "usd" },
		func(p *ProviderPriceSnapshot) { p.Currency = "US" },
		func(p *ProviderPriceSnapshot) { p.SourceHash = "sha256:source" },
		func(p *ProviderPriceSnapshot) { p.SourceHash = "sha256:" + strings.Repeat("g", 64) },
	} {
		p := exactPriceFixture()
		mutate(p)
		if p.Seal() == nil {
			t.Fatalf("invalid price accepted: %+v", p)
		}
		if _, err := p.QuoteCents(1, 0); err == nil {
			t.Fatal("invalid price quoted")
		}
	}
	for _, pair := range [][2]int64{{-1, 0}, {math.MaxInt64, 0}, {0, math.MaxInt64}} {
		p := exactPriceFixture()
		p.OutputTokenNanoCents = 4200
		if _, err := p.ExactCostNanoCents(pair[0], pair[1]); err == nil {
			t.Fatal("negative/overflow usage accepted")
		}
	}
	p := exactPriceFixture()
	p.InputTokenNanoCents, p.OutputTokenNanoCents = math.MaxInt64, 1
	if _, err := p.ExactCostNanoCents(1, 1); err == nil {
		t.Fatal("sum overflow accepted")
	}
	p.OutputTokenNanoCents, p.RequestNanoCents = 0, 1
	if _, err := p.ExactCostNanoCents(1, 0); err == nil {
		t.Fatal("request fee overflow accepted")
	}
}

func TestExactProviderPriceGoldenWireAndDigest(t *testing.T) {
	raw, err := os.ReadFile("testdata/provider_price_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var wire ProviderPriceSnapshot
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	p := exactPriceFixture()
	if err := p.Seal(); err != nil {
		t.Fatal(err)
	}
	if wire != *p {
		t.Fatalf("golden price differs from producer: %+v", p)
	}
	// The JSON-schema test reads these same bytes. Re-marshalling must not
	// discard unknown fields or change any typed field in the golden payload.
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(document)
	encoded, _ := json.Marshal(p)
	var produced map[string]any
	if err := json.Unmarshal(encoded, &produced); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(produced)
	if string(got) != string(want) {
		t.Fatalf("producer wire differs: %s", got)
	}
}

func TestExactProviderPriceDigestCoversVersionRatesAndValidity(t *testing.T) {
	p := exactPriceFixture()
	base := p.CanonicalDigest()
	for _, mutate := range []func(*ProviderPriceSnapshot){
		func(p *ProviderPriceSnapshot) { p.SchemaVersion = "other" },
		func(p *ProviderPriceSnapshot) { p.InputTokenNanoCents++ },
		func(p *ProviderPriceSnapshot) { p.OutputTokenNanoCents++ },
		func(p *ProviderPriceSnapshot) { p.RequestNanoCents++ },
		func(p *ProviderPriceSnapshot) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
		func(p *ProviderPriceSnapshot) { p.EffectiveAt = p.EffectiveAt.Add(time.Second) },
		func(p *ProviderPriceSnapshot) { p.CapturedAt = p.CapturedAt.Add(time.Second) },
		func(p *ProviderPriceSnapshot) { p.SourceURI += "/other" },
		func(p *ProviderPriceSnapshot) { p.SourceHash += "other" },
		func(p *ProviderPriceSnapshot) { p.ProviderTermsProfileID += "other" },
	} {
		copy := *p
		mutate(&copy)
		if copy.CanonicalDigest() == base {
			t.Fatal("authoritative change not covered")
		}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var got ProviderPriceSnapshot
	if err := json.Unmarshal(raw, &got); err != nil || got.CanonicalDigest() != base {
		t.Fatalf("round trip: %v", err)
	}
}
