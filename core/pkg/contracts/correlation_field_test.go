package contracts

import (
	"encoding/json"
	"strings"
	"testing"
)

// The correlation_id field (telemetry contract §2, C-2) must round-trip on
// all three contracts and stay absent from JSON when empty, so pre-existing
// receipts/decisions/packs are byte-identical after re-serialization.
func TestCorrelationIDRoundTrip(t *testing.T) {
	const corr = "d2f1c3a4-5b6e-4f70-8a91-b2c3d4e5f601"

	cases := []struct {
		name    string
		build   func() any
		rebuild func() any
	}{
		{"Receipt", func() any { return &Receipt{ReceiptID: "r1", CorrelationID: corr} }, func() any { return &Receipt{} }},
		{"DecisionRecord", func() any { return &DecisionRecord{ID: "d1", CorrelationID: corr} }, func() any { return &DecisionRecord{} }},
		{"EvidencePack", func() any { return &EvidencePack{PackID: "p1", CorrelationID: corr} }, func() any { return &EvidencePack{} }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.build())
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.Contains(string(raw), `"correlation_id":"`+corr+`"`) {
				t.Errorf("serialized %s missing correlation_id: %s", tc.name, raw)
			}

			got := tc.rebuild()
			if err := json.Unmarshal(raw, got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			reraw, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("re-marshal: %v", err)
			}
			if !strings.Contains(string(reraw), corr) {
				t.Errorf("%s lost correlation_id on round-trip", tc.name)
			}
		})
	}
}

func TestCorrelationIDOmittedWhenEmpty(t *testing.T) {
	for name, v := range map[string]any{
		"Receipt":        &Receipt{ReceiptID: "r1"},
		"DecisionRecord": &DecisionRecord{ID: "d1"},
		"EvidencePack":   &EvidencePack{PackID: "p1"},
	} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s marshal: %v", name, err)
		}
		if strings.Contains(string(raw), "correlation_id") {
			t.Errorf("%s must omit empty correlation_id, got: %s", name, raw)
		}
	}
}
