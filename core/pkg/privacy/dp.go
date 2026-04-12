package privacy

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"time"
)

// DPEngine applies differential privacy noise to compliance metrics.
// It uses the Laplace mechanism: noise is drawn from Laplace(0, sensitivity/epsilon)
// and added to the true value before release.
type DPEngine struct {
	config DPConfig
	clock  func() time.Time
	rng    func() float64 // source of uniform random values in (0, 1)
}

// NewDPEngine creates a new differential privacy engine with the given configuration.
func NewDPEngine(config DPConfig) *DPEngine {
	return &DPEngine{
		config: config,
		clock:  time.Now,
		rng:    cryptoRandFloat64,
	}
}

// WithClock overrides the clock for deterministic testing.
func (e *DPEngine) WithClock(clock func() time.Time) *DPEngine {
	e.clock = clock
	return e
}

// WithRNG overrides the random source for deterministic testing.
// The function must return values uniformly distributed in (0, 1).
func (e *DPEngine) WithRNG(rng func() float64) *DPEngine {
	e.rng = rng
	return e
}

// AddNoise adds calibrated Laplace noise to a metric value.
// The noise magnitude is sensitivity / epsilon, ensuring (epsilon, delta)-differential privacy.
func (e *DPEngine) AddNoise(metricName string, trueValue float64) *DPMetric {
	scale := e.config.Sensitivity / e.config.Epsilon
	noise := sampleLaplace(scale, e.rng)

	return &DPMetric{
		MetricName: metricName,
		TrueValue:  trueValue,
		NoisyValue: trueValue + noise,
		Epsilon:    e.config.Epsilon,
		Timestamp:  e.clock(),
	}
}

// PrivateComplianceScore returns a DP-protected compliance score.
// The trueScore is an integer (e.g., 0-100), and the result is a noisy float.
func (e *DPEngine) PrivateComplianceScore(framework string, trueScore int) *DPMetric {
	metricName := "compliance_score:" + framework
	return e.AddNoise(metricName, float64(trueScore))
}

// sampleLaplace draws a sample from the Laplace distribution Laplace(0, scale).
// Uses the inverse CDF method: if U ~ Uniform(0,1), then
// X = -scale * sign(U - 0.5) * ln(1 - 2|U - 0.5|)
func sampleLaplace(scale float64, rng func() float64) float64 {
	u := rng()
	// Clamp to avoid log(0).
	if u == 0.0 {
		u = 1e-15
	}
	if u == 1.0 {
		u = 1.0 - 1e-15
	}

	if u < 0.5 {
		// Left tail: negative values
		return scale * math.Log(2.0*u)
	}
	// Right tail: positive values
	return -scale * math.Log(2.0*(1.0-u))
}

// cryptoRandFloat64 produces a cryptographically random float64 in (0, 1)
// using crypto/rand.
func cryptoRandFloat64() float64 {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	// Convert to uint64, mask to 53-bit mantissa, divide by 2^53.
	bits := binary.LittleEndian.Uint64(buf[:])
	bits = bits >> 11 // keep 53 bits
	f := float64(bits) / float64(1<<53)
	// Ensure strictly in (0, 1).
	if f == 0.0 {
		f = 1e-15
	}
	return f
}
