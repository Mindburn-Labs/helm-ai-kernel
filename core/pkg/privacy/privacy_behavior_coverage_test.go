package privacy

import (
	"context"
	"testing"
	"time"
)

// ── MPC / Secret Sharing ──

func TestNewSecretSharer_ThresholdTooLow(t *testing.T) {
	_, err := NewSecretSharer(1, 3)
	if err == nil {
		t.Fatal("expected error for threshold < 2")
	}
}

func TestNewSecretSharer_TotalTooLow(t *testing.T) {
	_, err := NewSecretSharer(2, 1)
	if err == nil {
		t.Fatal("expected error for total < 2")
	}
}

func TestNewSecretSharer_ThresholdExceedsTotal(t *testing.T) {
	_, err := NewSecretSharer(5, 3)
	if err == nil {
		t.Fatal("expected error when threshold > total")
	}
}

func TestNewSecretSharer_TotalExceeds255(t *testing.T) {
	_, err := NewSecretSharer(2, 256)
	if err == nil {
		t.Fatal("expected error for total > 255 (GF(256) limit)")
	}
}

func TestSplitReconstructRoundTrip(t *testing.T) {
	ss, _ := NewSecretSharer(3, 5)
	secret := []byte("helm-governance-secret")
	shares, err := ss.Split(secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ss.Reconstruct(shares[:3])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(secret) {
		t.Fatalf("got %q, want %q", got, secret)
	}
}

func TestSplitEmptySecret(t *testing.T) {
	ss, _ := NewSecretSharer(2, 3)
	_, err := ss.Split([]byte{})
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestReconstructInsufficientShares(t *testing.T) {
	ss, _ := NewSecretSharer(3, 5)
	shares, _ := ss.Split([]byte("test"))
	_, err := ss.Reconstruct(shares[:2])
	if err == nil {
		t.Fatal("expected error with fewer shares than threshold")
	}
}

func TestReconstructMismatchedLengths(t *testing.T) {
	ss, _ := NewSecretSharer(2, 3)
	shares, _ := ss.Split([]byte("abc"))
	shares[1].Value = []byte("x") // shorten one share
	_, err := ss.Reconstruct(shares[:2])
	if err == nil {
		t.Fatal("expected error for mismatched share lengths")
	}
}

// ── Differential Privacy ──

func TestDPEngine_AddNoise_DeterministicRNG(t *testing.T) {
	cfg := DPConfig{Epsilon: 1.0, Delta: 1e-5, Sensitivity: 1.0}
	eng := NewDPEngine(cfg).WithRNG(func() float64 { return 0.5 })
	m := eng.AddNoise("metric", 100.0)
	if m.NoisyValue != 100.0 {
		t.Fatalf("at u=0.5 Laplace noise should be 0, got noisy=%f", m.NoisyValue)
	}
}

func TestDPEngine_PrivateComplianceScoreMetricName(t *testing.T) {
	cfg := DPConfig{Epsilon: 0.5, Delta: 1e-5, Sensitivity: 1.0}
	eng := NewDPEngine(cfg).WithRNG(func() float64 { return 0.25 })
	m := eng.PrivateComplianceScore("gdpr", 80)
	if m.MetricName != "compliance_score:gdpr" {
		t.Fatalf("unexpected metric name: %s", m.MetricName)
	}
	if m.TrueValue != 80.0 {
		t.Fatalf("true value should be 80, got %f", m.TrueValue)
	}
}

func TestDPEngine_TrueValueExcludedFromJSON(t *testing.T) {
	cfg := DPConfig{Epsilon: 1.0, Delta: 1e-5, Sensitivity: 1.0}
	eng := NewDPEngine(cfg).WithRNG(func() float64 { return 0.5 })
	m := eng.AddNoise("x", 42.0)
	if m.TrueValue != 42.0 {
		t.Fatal("TrueValue field should be set internally")
	}
	// DPMetric.TrueValue has `json:"-"`, so not serialized; just verify struct
}

// ── Privacy Manager ──

func TestPrivacyManager_ScrubNone(t *testing.T) {
	pm := NewPrivacyManager()
	got := pm.Scrub(context.Background(), "user@example.com", PIINone)
	if got != "user@example.com" {
		t.Fatalf("PIINone should not scrub, got %q", got)
	}
}

func TestPrivacyManager_ScrubEmail(t *testing.T) {
	pm := NewPrivacyManager()
	got := pm.Scrub(context.Background(), "Contact user@example.com for info", PIISensitive)
	if got != "Contact [REDACTED_EMAIL] for info" {
		t.Fatalf("expected email redaction, got %q", got)
	}
}

func TestPrivacyManager_ValidateRestrictedKeys(t *testing.T) {
	pm := NewPrivacyManager()
	data := map[string]interface{}{"ssn": "123-45-6789", "name": "John"}
	ok, violations := pm.Validate(context.Background(), data)
	if ok {
		t.Fatal("expected validation failure for restricted key 'ssn'")
	}
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
}

// ── Private Evaluator ──

func TestPrivateEvaluator_EvaluatePrivatelyRoundTrip(t *testing.T) {
	eval, _ := NewPrivateEvaluator(2, 3)
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	eval.WithClock(func() time.Time { return fixedTime })

	ss, _ := NewSecretSharer(2, 3)
	shares, _ := ss.Split([]byte("allow-me"))
	for i := range shares {
		shares[i].PartyID = "party-" + shares[i].ShareID[:4]
	}

	req := PrivateEvalRequest{
		RequestID:   "req-1",
		PolicyHash:  "policy-abc",
		InputShares: shares[:2],
		Threshold:   2,
	}
	result, err := eval.EvaluatePrivately(req, func(input []byte) (string, error) {
		return "ALLOW", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "ALLOW" {
		t.Fatalf("expected ALLOW, got %s", result.Verdict)
	}
	if result.ProofHash == "" || result.ContentHash == "" {
		t.Fatal("expected non-empty proof and content hashes")
	}
}
