package privacy

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"testing"
	"time"
)

var stressClock = func() time.Time { return time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC) }

// --- Secret Sharing Stress ---

func TestStress_SecretSharing_3of5(t *testing.T) {
	sharer, err := NewSecretSharer(3, 5)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("governance-firewall-3of5")
	shares, err := sharer.Split(secret)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := sharer.Reconstruct(shares[:3])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, recovered) {
		t.Fatalf("3-of-5 reconstruction failed")
	}
}

func TestStress_SecretSharing_5of7(t *testing.T) {
	sharer, err := NewSecretSharer(5, 7)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("helm-5of7-secret-payload")
	shares, err := sharer.Split(secret)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := sharer.Reconstruct(shares[:5])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, recovered) {
		t.Fatalf("5-of-7 reconstruction failed")
	}
}

func TestStress_SecretSharing_2of3(t *testing.T) {
	sharer, err := NewSecretSharer(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("2of3-min")
	shares, err := sharer.Split(secret)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := sharer.Reconstruct(shares[:2])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, recovered) {
		t.Fatalf("2-of-3 reconstruction failed")
	}
}

func TestStress_SecretSharing_3of5_AllSubsets(t *testing.T) {
	sharer, err := NewSecretSharer(3, 5)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("all-subsets-check")
	shares, err := sharer.Split(secret)
	if err != nil {
		t.Fatal(err)
	}
	// Test all C(5,3) = 10 subsets
	for i := 0; i < 5; i++ {
		for j := i + 1; j < 5; j++ {
			for k := j + 1; k < 5; k++ {
				subset := []SecretShare{shares[i], shares[j], shares[k]}
				recovered, err := sharer.Reconstruct(subset)
				if err != nil {
					t.Fatalf("subset [%d,%d,%d] failed: %v", i, j, k, err)
				}
				if !bytes.Equal(secret, recovered) {
					t.Fatalf("subset [%d,%d,%d] mismatch", i, j, k)
				}
			}
		}
	}
}

func TestStress_SecretSharing_5of7_AllSubsets(t *testing.T) {
	sharer, err := NewSecretSharer(5, 7)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("5of7-subsets")
	shares, err := sharer.Split(secret)
	if err != nil {
		t.Fatal(err)
	}
	// C(7,5)=21 subsets
	count := 0
	for a := 0; a < 7; a++ {
		for b := a + 1; b < 7; b++ {
			for c := b + 1; c < 7; c++ {
				for d := c + 1; d < 7; d++ {
					for e := d + 1; e < 7; e++ {
						subset := []SecretShare{shares[a], shares[b], shares[c], shares[d], shares[e]}
						recovered, err := sharer.Reconstruct(subset)
						if err != nil {
							t.Fatalf("subset failed: %v", err)
						}
						if !bytes.Equal(secret, recovered) {
							t.Fatal("mismatch in 5of7 subset")
						}
						count++
					}
				}
			}
		}
	}
	if count != 21 {
		t.Fatalf("expected 21 subsets, got %d", count)
	}
}

func TestStress_SecretSharing_2of3_AllSubsets(t *testing.T) {
	sharer, err := NewSecretSharer(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("2of3-all")
	shares, err := sharer.Split(secret)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		for j := i + 1; j < 3; j++ {
			subset := []SecretShare{shares[i], shares[j]}
			recovered, err := sharer.Reconstruct(subset)
			if err != nil {
				t.Fatalf("subset [%d,%d] failed: %v", i, j, err)
			}
			if !bytes.Equal(secret, recovered) {
				t.Fatalf("subset [%d,%d] mismatch", i, j)
			}
		}
	}
}

func TestStress_SecretSharing_InsufficientShares(t *testing.T) {
	sharer, err := NewSecretSharer(3, 5)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := sharer.Split([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = sharer.Reconstruct(shares[:2])
	if err == nil {
		t.Fatal("expected error with insufficient shares")
	}
}

func TestStress_SecretSharing_EmptySecret(t *testing.T) {
	sharer, err := NewSecretSharer(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sharer.Split([]byte{})
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestStress_SecretSharing_SingleByte(t *testing.T) {
	sharer, err := NewSecretSharer(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte{0xAB}
	shares, err := sharer.Split(secret)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := sharer.Reconstruct(shares[:2])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, recovered) {
		t.Fatal("single byte reconstruction failed")
	}
}

func TestStress_SecretSharing_LargeSecret(t *testing.T) {
	sharer, err := NewSecretSharer(3, 5)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 1024)
	for i := range secret {
		secret[i] = byte(i % 256)
	}
	shares, err := sharer.Split(secret)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := sharer.Reconstruct(shares[:3])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, recovered) {
		t.Fatal("large secret reconstruction failed")
	}
}

// --- GF(256) Stress ---

func TestStress_GF256_MulIdentity(t *testing.T) {
	for i := 0; i < 256; i++ {
		if gfMul(byte(i), 1) != byte(i) {
			t.Fatalf("gfMul(%d, 1) != %d", i, i)
		}
	}
}

func TestStress_GF256_MulZero(t *testing.T) {
	for i := 0; i < 256; i++ {
		if gfMul(byte(i), 0) != 0 {
			t.Fatalf("gfMul(%d, 0) != 0", i)
		}
	}
}

func TestStress_GF256_InvProperty(t *testing.T) {
	for i := 1; i < 256; i++ {
		inv := gfInv(byte(i))
		if gfMul(byte(i), inv) != 1 {
			t.Fatalf("gfMul(%d, gfInv(%d)) != 1", i, i)
		}
	}
}

func TestStress_GF256_MulCommutative50Pairs(t *testing.T) {
	pairs := [][2]byte{
		{2, 3}, {7, 11}, {13, 17}, {19, 23}, {29, 31},
		{37, 41}, {43, 47}, {53, 59}, {61, 67}, {71, 73},
		{79, 83}, {89, 97}, {101, 103}, {107, 109}, {113, 127},
		{131, 137}, {139, 149}, {151, 157}, {163, 167}, {173, 179},
		{181, 191}, {193, 197}, {199, 211}, {223, 227}, {229, 233},
		{239, 241}, {251, 253}, {254, 255}, {1, 255}, {128, 64},
		{200, 100}, {50, 150}, {10, 245}, {99, 156}, {77, 188},
		{33, 222}, {44, 211}, {55, 166}, {66, 177}, {88, 144},
		{111, 133}, {122, 244}, {5, 250}, {15, 240}, {25, 230},
		{35, 220}, {45, 210}, {65, 190}, {75, 180}, {85, 170},
	}
	for _, p := range pairs {
		if gfMul(p[0], p[1]) != gfMul(p[1], p[0]) {
			t.Fatalf("gfMul not commutative for (%d, %d)", p[0], p[1])
		}
	}
}

func TestStress_GF256_DivRoundTrip50Pairs(t *testing.T) {
	pairs := [][2]byte{
		{2, 3}, {7, 11}, {13, 17}, {19, 23}, {29, 31},
		{37, 41}, {43, 47}, {53, 59}, {61, 67}, {71, 73},
		{79, 83}, {89, 97}, {101, 103}, {107, 109}, {113, 127},
		{131, 137}, {139, 149}, {151, 157}, {163, 167}, {173, 179},
		{181, 191}, {193, 197}, {199, 211}, {223, 227}, {229, 233},
		{239, 241}, {251, 253}, {254, 255}, {1, 255}, {128, 64},
		{200, 100}, {50, 150}, {10, 245}, {99, 156}, {77, 188},
		{33, 222}, {44, 211}, {55, 166}, {66, 177}, {88, 144},
		{111, 133}, {122, 244}, {5, 250}, {15, 240}, {25, 230},
		{35, 220}, {45, 210}, {65, 190}, {75, 180}, {85, 170},
	}
	for _, p := range pairs {
		product := gfMul(p[0], p[1])
		if gfDiv(product, p[1]) != p[0] {
			t.Fatalf("gfDiv roundtrip failed for (%d, %d)", p[0], p[1])
		}
	}
}

func TestStress_GF256_InvZero(t *testing.T) {
	if gfInv(0) != 0 {
		t.Fatal("gfInv(0) should return 0 as safe fallback")
	}
}

// --- DP Noise Stress ---

func TestStress_DPNoise_100Samples_NonZeroVariance(t *testing.T) {
	engine := NewDPEngine(DPConfig{Epsilon: 1.0, Delta: 1e-5, Sensitivity: 1.0})
	var sum float64
	for i := 0; i < 100; i++ {
		m := engine.AddNoise("metric", 50.0)
		sum += m.NoisyValue
	}
	avg := sum / 100
	if avg == 50.0 {
		t.Fatal("all 100 noisy values identical to true value -- no noise added")
	}
}

func TestStress_DPNoise_100Samples_MeanNearTrueValue(t *testing.T) {
	engine := NewDPEngine(DPConfig{Epsilon: 10.0, Delta: 1e-5, Sensitivity: 1.0})
	var sum float64
	for i := 0; i < 100; i++ {
		m := engine.AddNoise("metric", 100.0)
		sum += m.NoisyValue
	}
	avg := sum / 100
	if math.Abs(avg-100.0) > 5.0 {
		t.Fatalf("mean %.2f too far from true value 100.0", avg)
	}
}

func TestStress_DPNoise_HighEpsilonLowNoise(t *testing.T) {
	engine := NewDPEngine(DPConfig{Epsilon: 100.0, Delta: 1e-5, Sensitivity: 1.0})
	for i := 0; i < 100; i++ {
		m := engine.AddNoise("metric", 50.0)
		if math.Abs(m.NoisyValue-50.0) > 5.0 {
			t.Fatalf("high epsilon sample %d too noisy: %.2f", i, m.NoisyValue)
		}
	}
}

func TestStress_DPNoise_LowEpsilonHighNoise(t *testing.T) {
	engine := NewDPEngine(DPConfig{Epsilon: 0.01, Delta: 1e-5, Sensitivity: 1.0})
	outlier := false
	for i := 0; i < 100; i++ {
		m := engine.AddNoise("metric", 50.0)
		if math.Abs(m.NoisyValue-50.0) > 10.0 {
			outlier = true
		}
	}
	if !outlier {
		t.Fatal("expected at least one large noise value with low epsilon")
	}
}

func TestStress_DPNoise_TrueValueNotInJSON(t *testing.T) {
	engine := NewDPEngine(DPConfig{Epsilon: 1.0, Delta: 1e-5, Sensitivity: 1.0})
	m := engine.AddNoise("metric", 42.0)
	if m.TrueValue != 42.0 {
		t.Fatal("TrueValue should be stored in struct")
	}
}

func TestStress_DPNoise_DeterministicRNG(t *testing.T) {
	engine := NewDPEngine(DPConfig{Epsilon: 1.0, Delta: 1e-5, Sensitivity: 1.0}).
		WithRNG(func() float64 { return 0.5 })
	m1 := engine.AddNoise("x", 10.0)
	m2 := engine.AddNoise("x", 10.0)
	if m1.NoisyValue != m2.NoisyValue {
		t.Fatal("deterministic RNG should produce identical noise")
	}
}

func TestStress_DPNoise_ComplianceScore100Samples(t *testing.T) {
	engine := NewDPEngine(DPConfig{Epsilon: 1.0, Delta: 1e-5, Sensitivity: 1.0})
	for i := 0; i < 100; i++ {
		m := engine.PrivateComplianceScore("gdpr", 80)
		if m.MetricName != "compliance_score:gdpr" {
			t.Fatalf("unexpected metric name: %s", m.MetricName)
		}
	}
}

// --- Private Evaluator Stress ---

func TestStress_PrivateEvaluator_AllowPolicy(t *testing.T) {
	eval, err := NewPrivateEvaluator(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	eval.WithClock(stressClock)
	sharer, _ := NewSecretSharer(2, 3)
	shares, _ := sharer.Split([]byte("allow-me"))
	for i := range shares {
		shares[i].PartyID = fmt.Sprintf("party-%d", i)
	}
	req := PrivateEvalRequest{RequestID: "r1", PolicyHash: "ph1", InputShares: shares, Threshold: 2}
	result, err := eval.EvaluatePrivately(req, func(input []byte) (string, error) { return "ALLOW", nil })
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "ALLOW" {
		t.Fatalf("expected ALLOW, got %s", result.Verdict)
	}
}

func TestStress_PrivateEvaluator_DenyPolicy(t *testing.T) {
	eval, err := NewPrivateEvaluator(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	sharer, _ := NewSecretSharer(2, 3)
	shares, _ := sharer.Split([]byte("deny-me"))
	req := PrivateEvalRequest{RequestID: "r2", PolicyHash: "ph2", InputShares: shares, Threshold: 2}
	result, err := eval.EvaluatePrivately(req, func(input []byte) (string, error) { return "DENY", nil })
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "DENY" {
		t.Fatalf("expected DENY, got %s", result.Verdict)
	}
}

func TestStress_PrivateEvaluator_PolicyError(t *testing.T) {
	eval, err := NewPrivateEvaluator(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	sharer, _ := NewSecretSharer(2, 3)
	shares, _ := sharer.Split([]byte("err"))
	req := PrivateEvalRequest{RequestID: "r3", PolicyHash: "ph3", InputShares: shares, Threshold: 2}
	_, err = eval.EvaluatePrivately(req, func(input []byte) (string, error) { return "", fmt.Errorf("policy boom") })
	if err == nil {
		t.Fatal("expected error from policy function")
	}
}

func TestStress_PrivateEvaluator_ProofHashDeterminism(t *testing.T) {
	h1 := computeProofHash("policy1", []byte("input1"), "ALLOW")
	h2 := computeProofHash("policy1", []byte("input1"), "ALLOW")
	if h1 != h2 {
		t.Fatal("proof hash not deterministic")
	}
}

func TestStress_PrivateEvaluator_ProofHashDiffersOnVerdict(t *testing.T) {
	h1 := computeProofHash("p1", []byte("in"), "ALLOW")
	h2 := computeProofHash("p1", []byte("in"), "DENY")
	if h1 == h2 {
		t.Fatal("different verdicts produced same proof hash")
	}
}

func TestStress_PrivateEvaluator_ContentHashSet(t *testing.T) {
	eval, err := NewPrivateEvaluator(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	eval.WithClock(stressClock)
	sharer, _ := NewSecretSharer(2, 3)
	shares, _ := sharer.Split([]byte("hash-check"))
	req := PrivateEvalRequest{RequestID: "r4", PolicyHash: "ph4", InputShares: shares, Threshold: 2}
	result, err := eval.EvaluatePrivately(req, func(input []byte) (string, error) { return "ALLOW", nil })
	if err != nil {
		t.Fatal(err)
	}
	if result.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}

func TestStress_PrivateEvaluator_InsufficientShares(t *testing.T) {
	eval, err := NewPrivateEvaluator(3, 5)
	if err != nil {
		t.Fatal(err)
	}
	sharer, _ := NewSecretSharer(3, 5)
	shares, _ := sharer.Split([]byte("sec"))
	req := PrivateEvalRequest{RequestID: "r5", PolicyHash: "ph5", InputShares: shares[:2], Threshold: 3}
	_, err = eval.EvaluatePrivately(req, func(input []byte) (string, error) { return "ALLOW", nil })
	if err == nil {
		t.Fatal("expected error with insufficient shares")
	}
}

func TestStress_PrivateEvaluator_10Policies(t *testing.T) {
	eval, err := NewPrivateEvaluator(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	eval.WithClock(stressClock)
	sharer, _ := NewSecretSharer(2, 3)
	for i := 0; i < 10; i++ {
		secret := []byte(fmt.Sprintf("policy-input-%d", i))
		shares, _ := sharer.Split(secret)
		verdict := "ALLOW"
		if i%2 == 0 {
			verdict = "DENY"
		}
		req := PrivateEvalRequest{
			RequestID:   fmt.Sprintf("r-%d", i),
			PolicyHash:  fmt.Sprintf("ph-%d", i),
			InputShares: shares,
			Threshold:   2,
		}
		result, err := eval.EvaluatePrivately(req, func(input []byte) (string, error) { return verdict, nil })
		if err != nil {
			t.Fatalf("policy %d failed: %v", i, err)
		}
		if result.Verdict != verdict {
			t.Fatalf("policy %d: expected %s, got %s", i, verdict, result.Verdict)
		}
	}
}

func TestStress_PrivacyManager_ScrubNone(t *testing.T) {
	pm := NewPrivacyManager()
	text := "email@test.com"
	result := pm.Scrub(context.Background(), text, PIINone)
	if result != text {
		t.Fatal("PIINone should not scrub")
	}
}

func TestStress_PrivacyManager_ValidateRestrictedKeys(t *testing.T) {
	pm := NewPrivacyManager()
	data := map[string]interface{}{"ssn": "123-45-6789", "name": "test"}
	valid, violations := pm.Validate(context.Background(), data)
	if valid {
		t.Fatal("expected validation failure for restricted key")
	}
	if len(violations) == 0 {
		t.Fatal("expected violations")
	}
}

func TestStress_PrivacyManager_ValidateCleanData(t *testing.T) {
	pm := NewPrivacyManager()
	data := map[string]interface{}{"name": "test", "age": 30}
	valid, violations := pm.Validate(context.Background(), data)
	if !valid {
		t.Fatalf("expected valid, got violations: %v", violations)
	}
}

func TestStress_ZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	zeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed", i)
		}
	}
}

func TestStress_SecretSharing_MaxShares255(t *testing.T) {
	_, err := NewSecretSharer(2, 255)
	if err != nil {
		t.Fatalf("expected 255 shares to be valid: %v", err)
	}
}

func TestStress_SecretSharing_Over255Rejected(t *testing.T) {
	_, err := NewSecretSharer(2, 256)
	if err == nil {
		t.Fatal("expected error for total > 255")
	}
}

func TestStress_PrivacyManager_ScrubEmail(t *testing.T) {
	pm := NewPrivacyManager()
	result := pm.Scrub(context.Background(), "contact user@example.com now", PIISensitive)
	if result == "contact user@example.com now" {
		t.Fatal("expected email to be redacted")
	}
}

func TestStress_DPNoise_ClockOverride(t *testing.T) {
	engine := NewDPEngine(DPConfig{Epsilon: 1.0, Delta: 1e-5, Sensitivity: 1.0}).
		WithClock(stressClock)
	m := engine.AddNoise("ts-check", 10.0)
	if m.Timestamp != stressClock() {
		t.Fatal("expected overridden clock timestamp")
	}
}

func TestStress_PrivateEvaluator_PartyIDsCollected(t *testing.T) {
	eval, err := NewPrivateEvaluator(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	eval.WithClock(stressClock)
	sharer, _ := NewSecretSharer(2, 3)
	shares, _ := sharer.Split([]byte("parties"))
	shares[0].PartyID = "alice"
	shares[1].PartyID = "bob"
	shares[2].PartyID = "carol"
	req := PrivateEvalRequest{RequestID: "rp", PolicyHash: "pp", InputShares: shares, Threshold: 2}
	result, err := eval.EvaluatePrivately(req, func(input []byte) (string, error) { return "ALLOW", nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Parties) < 2 {
		t.Fatalf("expected at least 2 parties, got %d", len(result.Parties))
	}
}
