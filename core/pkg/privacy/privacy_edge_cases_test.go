package privacy

import (
	"math"
	"testing"
	"time"
)

func TestDeepSecretSharingThreshold5of7(t *testing.T) {
	sharer, err := NewSecretSharer(5, 7)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("HELM-governance-secret-data!!!")
	shares, err := sharer.Split(secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 7 {
		t.Fatalf("expected 7 shares, got %d", len(shares))
	}
}

func TestDeepReconstructExactly5of7(t *testing.T) {
	sharer, _ := NewSecretSharer(5, 7)
	secret := []byte("exact-threshold-test")
	shares, _ := sharer.Split(secret)
	recovered, err := sharer.Reconstruct(shares[:5])
	if err != nil {
		t.Fatal(err)
	}
	if string(recovered) != string(secret) {
		t.Fatalf("reconstruction failed: got %q", string(recovered))
	}
}

func TestDeepReconstructFailsBelow5of7(t *testing.T) {
	sharer, _ := NewSecretSharer(5, 7)
	secret := []byte("not-enough-shares")
	shares, _ := sharer.Split(secret)
	_, err := sharer.Reconstruct(shares[:4])
	if err == nil {
		t.Fatal("should reject fewer than threshold shares")
	}
}

func TestDeepReconstructWithExtraShares(t *testing.T) {
	sharer, _ := NewSecretSharer(5, 7)
	secret := []byte("all-7-shares")
	shares, _ := sharer.Split(secret)
	recovered, err := sharer.Reconstruct(shares)
	if err != nil {
		t.Fatal(err)
	}
	if string(recovered) != string(secret) {
		t.Fatalf("reconstruction with 7 shares failed: got %q", string(recovered))
	}
}

func TestDeepReconstructNonContiguousShares(t *testing.T) {
	sharer, _ := NewSecretSharer(5, 7)
	secret := []byte("non-contiguous")
	shares, _ := sharer.Split(secret)
	subset := []SecretShare{shares[0], shares[2], shares[3], shares[5], shares[6]}
	recovered, err := sharer.Reconstruct(subset)
	if err != nil {
		t.Fatal(err)
	}
	if string(recovered) != string(secret) {
		t.Fatalf("non-contiguous reconstruction failed: got %q", string(recovered))
	}
}

func TestDeepGF256IdentityProperty(t *testing.T) {
	for a := 1; a < 256; a++ {
		if gfMul(byte(a), 1) != byte(a) {
			t.Fatalf("gfMul(%d, 1) != %d", a, a)
		}
	}
}

func TestDeepGF256InverseProperty(t *testing.T) {
	for a := 1; a < 256; a++ {
		inv := gfInv(byte(a))
		product := gfMul(byte(a), inv)
		if product != 1 {
			t.Fatalf("gfMul(%d, gfInv(%d)) = %d, want 1", a, a, product)
		}
	}
}

func TestDeepGF256ZeroMultiplication(t *testing.T) {
	for a := 0; a < 256; a++ {
		if gfMul(byte(a), 0) != 0 {
			t.Fatalf("gfMul(%d, 0) should be 0", a)
		}
	}
}

func TestDeepGF256Commutativity(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if gfMul(byte(a), byte(b)) != gfMul(byte(b), byte(a)) {
				t.Fatalf("gfMul not commutative: a=%d, b=%d", a, b)
			}
		}
	}
}

func TestDeepDPNoiseDistribution100Samples(t *testing.T) {
	cfg := DPConfig{Epsilon: 1.0, Delta: 1e-5, Sensitivity: 1.0}
	engine := NewDPEngine(cfg)
	trueVal := 50.0
	maxDeviation := 20.0

	for i := 0; i < 100; i++ {
		metric := engine.AddNoise("deep_score", trueVal)
		noise := metric.NoisyValue - trueVal
		if math.Abs(noise) > maxDeviation {
			t.Fatalf("sample %d: noise=%f exceeds %f", i, noise, maxDeviation)
		}
	}
}

func TestDeepDPNoiseMeanApproximatelyZero(t *testing.T) {
	cfg := DPConfig{Epsilon: 1.0, Delta: 1e-5, Sensitivity: 1.0}
	engine := NewDPEngine(cfg)
	sum := 0.0
	n := 1000
	for i := 0; i < n; i++ {
		metric := engine.AddNoise("deep_x", 0.0)
		sum += metric.NoisyValue
	}
	mean := sum / float64(n)
	if math.Abs(mean) > 0.5 {
		t.Fatalf("mean noise too far from zero: %f", mean)
	}
}

func TestDeepDPDeterministicWithFixedRNG(t *testing.T) {
	cfg := DPConfig{Epsilon: 1.0, Delta: 1e-5, Sensitivity: 1.0}
	engine := NewDPEngine(cfg).WithRNG(func() float64 { return 0.75 })
	a := engine.AddNoise("deep_x", 10.0)
	b := engine.AddNoise("deep_x", 10.0)
	if a.NoisyValue != b.NoisyValue {
		t.Fatal("fixed RNG should produce identical noise")
	}
}

func TestDeepDPTrueValueStored(t *testing.T) {
	cfg := DPConfig{Epsilon: 1.0, Delta: 1e-5, Sensitivity: 1.0}
	engine := NewDPEngine(cfg)
	metric := engine.AddNoise("deep_secret", 42.0)
	if metric.TrueValue != 42.0 {
		t.Fatal("TrueValue should be stored in struct")
	}
}

func TestDeepPrivateEvaluatorWithRealPolicy(t *testing.T) {
	eval, err := NewPrivateEvaluator(3, 5)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	eval.WithClock(func() time.Time { return ts })

	sharer, _ := NewSecretSharer(3, 5)
	secret := []byte("admin-action-delete-production")
	shares, _ := sharer.Split(secret)

	for i := range shares {
		shares[i].PartyID = "party-" + shares[i].ShareID[:4]
	}

	policyFn := func(input []byte) (string, error) {
		if len(input) > 10 {
			return "DENY", nil
		}
		return "ALLOW", nil
	}

	req := PrivateEvalRequest{
		RequestID:   "deep-req-1",
		PolicyHash:  "deep-policy-hash",
		InputShares: shares[:3],
		PartyIDs:    []string{"p1", "p2", "p3"},
		Threshold:   3,
	}
	result, err := eval.EvaluatePrivately(req, policyFn)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "DENY" {
		t.Fatalf("expected DENY, got %s", result.Verdict)
	}
	if result.ProofHash == "" {
		t.Fatal("proof hash should be set")
	}
}

func TestDeepPrivateEvaluatorAllowVerdict(t *testing.T) {
	eval, _ := NewPrivateEvaluator(2, 3)
	sharer, _ := NewSecretSharer(2, 3)
	shares, _ := sharer.Split([]byte("ok"))

	req := PrivateEvalRequest{
		RequestID: "deep-r2", PolicyHash: "ph", InputShares: shares[:2], Threshold: 2,
	}
	result, _ := eval.EvaluatePrivately(req, func([]byte) (string, error) { return "ALLOW", nil })
	if result.Verdict != "ALLOW" {
		t.Fatalf("expected ALLOW, got %s", result.Verdict)
	}
}

func TestDeepPrivateEvaluatorTooFewShares(t *testing.T) {
	eval, _ := NewPrivateEvaluator(3, 5)
	sharer, _ := NewSecretSharer(3, 5)
	shares, _ := sharer.Split([]byte("x"))

	req := PrivateEvalRequest{
		RequestID: "deep-r3", PolicyHash: "ph", InputShares: shares[:2], Threshold: 3,
	}
	_, err := eval.EvaluatePrivately(req, func([]byte) (string, error) { return "ALLOW", nil })
	if err == nil {
		t.Fatal("should reject too few shares")
	}
}

func TestDeepSecretSharerRejectsThresholdBelow2(t *testing.T) {
	_, err := NewSecretSharer(1, 3)
	if err == nil {
		t.Fatal("threshold=1 should be rejected")
	}
}

func TestDeepGF256DivisionProperty(t *testing.T) {
	for a := 1; a < 256; a++ {
		if gfDiv(byte(a), byte(a)) != 1 {
			t.Fatalf("gfDiv(%d, %d) should be 1", a, a)
		}
	}
}

func TestDeepSecretSharerMaxTotal255(t *testing.T) {
	_, err := NewSecretSharer(2, 256)
	if err == nil {
		t.Fatal("total > 255 should be rejected (GF(256) constraint)")
	}
}

func TestDeepSecretSharerRejectsTotalBelow2(t *testing.T) {
	_, err := NewSecretSharer(2, 1)
	if err == nil {
		t.Fatal("total < threshold should be rejected")
	}
}

func TestDeepSecretSharerRejectsThresholdExceedsTotal(t *testing.T) {
	_, err := NewSecretSharer(5, 3)
	if err == nil {
		t.Fatal("threshold > total should be rejected")
	}
}

func TestDeepSecretSharerRejectsEmptySecret(t *testing.T) {
	sharer, _ := NewSecretSharer(2, 3)
	_, err := sharer.Split([]byte{})
	if err == nil {
		t.Fatal("should reject empty secret")
	}
}

func TestDeepDPComplianceScoreMetricName(t *testing.T) {
	cfg := DPConfig{Epsilon: 0.5, Delta: 1e-5, Sensitivity: 1.0}
	engine := NewDPEngine(cfg)
	metric := engine.PrivateComplianceScore("GDPR", 85)
	if metric.MetricName != "compliance_score:GDPR" {
		t.Fatalf("metric name = %q", metric.MetricName)
	}
}

func TestDeepDPHighEpsilonLessNoise(t *testing.T) {
	lowEps := NewDPEngine(DPConfig{Epsilon: 0.01, Sensitivity: 1.0})
	highEps := NewDPEngine(DPConfig{Epsilon: 100.0, Sensitivity: 1.0})

	lowVariance := 0.0
	highVariance := 0.0
	for i := 0; i < 500; i++ {
		lowVariance += math.Abs(lowEps.AddNoise("deep_x", 0).NoisyValue)
		highVariance += math.Abs(highEps.AddNoise("deep_x", 0).NoisyValue)
	}
	if highVariance > lowVariance {
		t.Fatal("high epsilon should produce less noise than low epsilon")
	}
}

func TestDeepPrivateEvaluatorContentHashSet(t *testing.T) {
	eval, _ := NewPrivateEvaluator(2, 3)
	sharer, _ := NewSecretSharer(2, 3)
	shares, _ := sharer.Split([]byte("data"))
	req := PrivateEvalRequest{
		RequestID: "deep-r4", PolicyHash: "ph", InputShares: shares[:2], Threshold: 2,
	}
	result, _ := eval.EvaluatePrivately(req, func([]byte) (string, error) { return "ALLOW", nil })
	if result.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}
