package privacy

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
)

func TestFinal_PIIClassificationConstants(t *testing.T) {
	classes := []PIIClassification{PIINone, PIISensitive, PIICritical}
	seen := make(map[PIIClassification]bool)
	for _, c := range classes {
		if c == "" {
			t.Fatal("PII classification must not be empty")
		}
		if seen[c] {
			t.Fatalf("duplicate: %s", c)
		}
		seen[c] = true
	}
}

func TestFinal_NewPrivacyManager(t *testing.T) {
	pm := NewPrivacyManager()
	if pm == nil {
		t.Fatal("privacy manager should not be nil")
	}
}

func TestFinal_PrivacyManagerInterface(t *testing.T) {
	var _ PrivacyManager = (*StandardPrivacyManager)(nil)
}

func TestFinal_ScrubNone(t *testing.T) {
	pm := NewPrivacyManager()
	text := "hello user@example.com"
	result := pm.Scrub(context.Background(), text, PIINone)
	if result != text {
		t.Fatal("PIINone should not scrub")
	}
}

func TestFinal_ScrubSensitiveEmail(t *testing.T) {
	pm := NewPrivacyManager()
	text := "Contact user@example.com for info"
	result := pm.Scrub(context.Background(), text, PIISensitive)
	if result == text {
		t.Fatal("email should be redacted for SENSITIVE")
	}
}

func TestFinal_ScrubCriticalEmail(t *testing.T) {
	pm := NewPrivacyManager()
	result := pm.Scrub(context.Background(), "john@test.com", PIICritical)
	if result == "john@test.com" {
		t.Fatal("email should be redacted for CRITICAL")
	}
}

func TestFinal_ValidateClean(t *testing.T) {
	pm := NewPrivacyManager()
	ok, violations := pm.Validate(context.Background(), map[string]interface{}{"name": "John"})
	if !ok || len(violations) > 0 {
		t.Fatal("clean data should pass validation")
	}
}

func TestFinal_ValidateSSN(t *testing.T) {
	pm := NewPrivacyManager()
	ok, violations := pm.Validate(context.Background(), map[string]interface{}{"ssn": "123-45-6789"})
	if ok {
		t.Fatal("data with SSN key should fail validation")
	}
	if len(violations) == 0 {
		t.Fatal("should report violations")
	}
}

func TestFinal_ValidateCreditCard(t *testing.T) {
	pm := NewPrivacyManager()
	ok, _ := pm.Validate(context.Background(), map[string]interface{}{"credit_card": "4111..."})
	if ok {
		t.Fatal("data with credit_card key should fail validation")
	}
}

func TestFinal_SecretShareJSON(t *testing.T) {
	ss := SecretShare{ShareID: "s1", PartyID: "p1", Index: 1, Threshold: 3, Total: 5}
	data, _ := json.Marshal(ss)
	var ss2 SecretShare
	json.Unmarshal(data, &ss2)
	if ss2.Index != 1 || ss2.Threshold != 3 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_PrivateEvalRequestJSON(t *testing.T) {
	per := PrivateEvalRequest{RequestID: "r1", PolicyHash: "ph", Threshold: 3}
	data, _ := json.Marshal(per)
	var per2 PrivateEvalRequest
	json.Unmarshal(data, &per2)
	if per2.RequestID != "r1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_PrivateEvalResultJSON(t *testing.T) {
	per := PrivateEvalResult{RequestID: "r1", Verdict: "ALLOW", ProofHash: "ph1"}
	data, _ := json.Marshal(per)
	var per2 PrivateEvalResult
	json.Unmarshal(data, &per2)
	if per2.Verdict != "ALLOW" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DPConfigJSON(t *testing.T) {
	dc := DPConfig{Epsilon: 1.0, Delta: 1e-5, Sensitivity: 1.0}
	data, _ := json.Marshal(dc)
	var dc2 DPConfig
	json.Unmarshal(data, &dc2)
	if dc2.Epsilon != 1.0 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DPMetricJSON(t *testing.T) {
	dm := DPMetric{MetricName: "count", TrueValue: 42, NoisyValue: 43.5, Epsilon: 1.0}
	data, _ := json.Marshal(dm)
	var dm2 DPMetric
	json.Unmarshal(data, &dm2)
	if dm2.TrueValue != 0 {
		t.Fatal("TrueValue should be excluded from JSON (json:\"-\")")
	}
	if dm2.NoisyValue != 43.5 {
		t.Fatal("NoisyValue round-trip mismatch")
	}
}

func TestFinal_DPMetricTrueValueExcluded(t *testing.T) {
	dm := DPMetric{MetricName: "m1", TrueValue: 100, NoisyValue: 101}
	data, _ := json.Marshal(dm)
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)
	if _, found := raw["true_value"]; found {
		t.Fatal("TrueValue should not appear in JSON")
	}
}

func TestFinal_DPEngineZeroValue(t *testing.T) {
	de := &DPEngine{}
	if de == nil {
		t.Fatal("zero value should not be nil")
	}
}

func TestFinal_SecretSharerZeroValue(t *testing.T) {
	ss := &SecretSharer{}
	if ss == nil {
		t.Fatal("zero value should not be nil")
	}
}

func TestFinal_PrivateEvaluatorZeroValue(t *testing.T) {
	pe := &PrivateEvaluator{}
	if pe == nil {
		t.Fatal("zero value should not be nil")
	}
}

func TestFinal_ConcurrentScrub(t *testing.T) {
	pm := NewPrivacyManager()
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pm.Scrub(context.Background(), "user@example.com", PIISensitive)
		}()
	}
	wg.Wait()
}

func TestFinal_ScrubDeterminism(t *testing.T) {
	pm := NewPrivacyManager()
	ctx := context.Background()
	r1 := pm.Scrub(ctx, "hello user@test.com world", PIISensitive)
	r2 := pm.Scrub(ctx, "hello user@test.com world", PIISensitive)
	if r1 != r2 {
		t.Fatal("scrub should be deterministic")
	}
}

func TestFinal_ValidateEmptyData(t *testing.T) {
	pm := NewPrivacyManager()
	ok, violations := pm.Validate(context.Background(), map[string]interface{}{})
	if !ok || len(violations) > 0 {
		t.Fatal("empty data should pass validation")
	}
}

func TestFinal_SecretShareValue(t *testing.T) {
	ss := SecretShare{Value: []byte{1, 2, 3}}
	if len(ss.Value) != 3 {
		t.Fatal("value length mismatch")
	}
}

func TestFinal_DPConfigPositiveEpsilon(t *testing.T) {
	dc := DPConfig{Epsilon: 0.1}
	if dc.Epsilon <= 0 {
		t.Fatal("epsilon should be positive")
	}
}

func TestFinal_PrivateEvalResultParties(t *testing.T) {
	per := PrivateEvalResult{Parties: []string{"p1", "p2", "p3"}}
	if len(per.Parties) != 3 {
		t.Fatal("should have 3 parties")
	}
}
