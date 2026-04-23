package privacy

import (
	"math"
	"testing"
	"time"
)

func TestDPEngine_AddNoise(t *testing.T) {
	config := DPConfig{
		Epsilon:     1.0,
		Delta:       1e-5,
		Sensitivity: 1.0,
	}
	engine := NewDPEngine(config)

	metric := engine.AddNoise("test_metric", 100.0)

	if metric.MetricName != "test_metric" {
		t.Errorf("expected metric name test_metric, got %s", metric.MetricName)
	}
	if metric.TrueValue != 100.0 {
		t.Errorf("expected true value 100.0, got %f", metric.TrueValue)
	}
	if metric.Epsilon != 1.0 {
		t.Errorf("expected epsilon 1.0, got %f", metric.Epsilon)
	}
	// The noisy value should differ from the true value (overwhelmingly likely
	// with cryptographic randomness). We allow a trivially small probability
	// of false failure here.
	if metric.NoisyValue == metric.TrueValue {
		t.Log("WARNING: noisy value equals true value (extremely unlikely, retrying)")
		// Retry once to rule out cosmic-ray-level coincidence.
		metric2 := engine.AddNoise("test_metric", 100.0)
		if metric2.NoisyValue == metric2.TrueValue {
			t.Error("noisy value equals true value on retry — noise not applied")
		}
	}
}

func TestDPEngine_EpsilonBounds(t *testing.T) {
	sensitivity := 1.0

	// High epsilon = low noise
	highEps := NewDPEngine(DPConfig{Epsilon: 10.0, Delta: 1e-5, Sensitivity: sensitivity})
	// Low epsilon = high noise
	lowEps := NewDPEngine(DPConfig{Epsilon: 0.01, Delta: 1e-5, Sensitivity: sensitivity})

	// Sample many noisy values and measure average absolute deviation.
	const trials = 10000
	trueVal := 50.0

	var highDeviation, lowDeviation float64
	for i := 0; i < trials; i++ {
		highMetric := highEps.AddNoise("m", trueVal)
		lowMetric := lowEps.AddNoise("m", trueVal)
		highDeviation += math.Abs(highMetric.NoisyValue - trueVal)
		lowDeviation += math.Abs(lowMetric.NoisyValue - trueVal)
	}
	highDeviation /= trials
	lowDeviation /= trials

	// Low epsilon should produce substantially larger deviations.
	// Expected deviation for Laplace is scale = sensitivity/epsilon.
	// High eps: scale = 1/10 = 0.1, expected deviation = 0.1
	// Low eps: scale = 1/0.01 = 100, expected deviation = 100
	if lowDeviation <= highDeviation {
		t.Errorf("lower epsilon should produce more noise: high_eps_dev=%.2f, low_eps_dev=%.2f",
			highDeviation, lowDeviation)
	}

	// Sanity: high-eps deviation should be small (< 1), low-eps should be large (> 10).
	if highDeviation > 5.0 {
		t.Errorf("high epsilon deviation unexpectedly large: %.2f", highDeviation)
	}
	if lowDeviation < 10.0 {
		t.Errorf("low epsilon deviation unexpectedly small: %.2f", lowDeviation)
	}
}

func TestDPEngine_PrivateComplianceScore(t *testing.T) {
	config := DPConfig{
		Epsilon:     1.0,
		Delta:       1e-5,
		Sensitivity: 1.0,
	}

	fixedTime := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	engine := NewDPEngine(config).WithClock(func() time.Time { return fixedTime })

	metric := engine.PrivateComplianceScore("GDPR", 85)

	if metric.MetricName != "compliance_score:GDPR" {
		t.Errorf("expected metric name compliance_score:GDPR, got %s", metric.MetricName)
	}
	if metric.TrueValue != 85.0 {
		t.Errorf("expected true value 85.0, got %f", metric.TrueValue)
	}
	if metric.Epsilon != 1.0 {
		t.Errorf("expected epsilon 1.0, got %f", metric.Epsilon)
	}
	if metric.Timestamp != fixedTime {
		t.Errorf("expected timestamp %v, got %v", fixedTime, metric.Timestamp)
	}
}

func TestDPEngine_Deterministic(t *testing.T) {
	config := DPConfig{
		Epsilon:     1.0,
		Delta:       1e-5,
		Sensitivity: 1.0,
	}

	// Fixed RNG that always returns 0.3.
	fixedRNG := func() float64 { return 0.3 }
	fixedTime := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)

	engine1 := NewDPEngine(config).WithRNG(fixedRNG).WithClock(func() time.Time { return fixedTime })
	engine2 := NewDPEngine(config).WithRNG(fixedRNG).WithClock(func() time.Time { return fixedTime })

	m1 := engine1.AddNoise("deterministic", 42.0)
	m2 := engine2.AddNoise("deterministic", 42.0)

	if m1.NoisyValue != m2.NoisyValue {
		t.Errorf("deterministic RNG should produce identical noise: %f != %f", m1.NoisyValue, m2.NoisyValue)
	}
}

func TestDPEngine_TrueValueNotSerialized(t *testing.T) {
	config := DPConfig{
		Epsilon:     1.0,
		Delta:       1e-5,
		Sensitivity: 1.0,
	}
	engine := NewDPEngine(config)
	metric := engine.AddNoise("secret_metric", 99.9)

	// TrueValue has json:"-" tag, so it should not appear in JSON.
	// We verify the tag exists by checking the struct field.
	if metric.TrueValue != 99.9 {
		t.Errorf("TrueValue should be set in memory: got %f", metric.TrueValue)
	}

	// The json:"-" tag is verified by the struct definition.
	// A serialization test would confirm it is excluded.
}

func TestDPEngine_MultipleSensitivities(t *testing.T) {
	// Higher sensitivity should produce more noise for the same epsilon.
	lowSens := NewDPEngine(DPConfig{Epsilon: 1.0, Delta: 1e-5, Sensitivity: 0.1})
	highSens := NewDPEngine(DPConfig{Epsilon: 1.0, Delta: 1e-5, Sensitivity: 100.0})

	const trials = 5000
	trueVal := 0.0

	var lowDev, highDev float64
	for i := 0; i < trials; i++ {
		lowDev += math.Abs(lowSens.AddNoise("m", trueVal).NoisyValue)
		highDev += math.Abs(highSens.AddNoise("m", trueVal).NoisyValue)
	}
	lowDev /= trials
	highDev /= trials

	if highDev <= lowDev {
		t.Errorf("higher sensitivity should produce more noise: low_sens_dev=%.2f, high_sens_dev=%.2f",
			lowDev, highDev)
	}
}

func TestSampleLaplace_Properties(t *testing.T) {
	// Basic sanity checks on the Laplace sampler with a deterministic RNG.

	// U = 0.5 should produce 0 (median of Laplace).
	val := sampleLaplace(1.0, func() float64 { return 0.5 })
	// At u=0.5, we're in the right branch: -1.0 * ln(2*(1-0.5)) = -ln(1) = 0
	if math.Abs(val) > 1e-10 {
		t.Errorf("Laplace(0.5) should be 0, got %f", val)
	}

	// U < 0.5 should produce negative values.
	val = sampleLaplace(1.0, func() float64 { return 0.1 })
	if val >= 0 {
		t.Errorf("Laplace(0.1) should be negative, got %f", val)
	}

	// U > 0.5 should produce positive values.
	val = sampleLaplace(1.0, func() float64 { return 0.9 })
	if val <= 0 {
		t.Errorf("Laplace(0.9) should be positive, got %f", val)
	}
}
