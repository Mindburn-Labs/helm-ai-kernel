// Package kernel provides deterministic PRNG for reproducible operations.
// Per Section 2.4 - Seed Policy and PRNG
package kernel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
)

// PRNGAlgorithm defines approved PRNG algorithms.
type PRNGAlgorithm string

const (
	// PRNGAlgorithmChaCha20 - ChaCha20-based PRNG
	PRNGAlgorithmChaCha20 PRNGAlgorithm = "chacha20"
	// PRNGAlgorithmHMACSHA256 - HMAC-SHA256 based PRNG
	PRNGAlgorithmHMACSHA256 PRNGAlgorithm = "hmac_sha256"
)

// SeedDerivation defines how seeds are derived.
type SeedDerivation string

const (
	// SeedDerivationLoopID - seed derived from loop ID
	SeedDerivationLoopID SeedDerivation = "loop_id"
	// SeedDerivationParentSeed - seed derived from parent
	SeedDerivationParentSeed SeedDerivation = "parent_seed"
	// SeedDerivationRequestHash - seed derived from request hash
	SeedDerivationRequestHash SeedDerivation = "request_hash"
)

// PRNGConfig defines the PRNG configuration.
type PRNGConfig struct {
	Algorithm   PRNGAlgorithm  `json:"algorithm"`
	SeedLength  int            `json:"seed_length_bytes"`
	Derivation  SeedDerivation `json:"derivation"`
	RecordToLog bool           `json:"record_to_log"`
}

// DefaultPRNGConfig returns the default PRNG configuration.
func DefaultPRNGConfig() PRNGConfig {
	return PRNGConfig{
		Algorithm:   PRNGAlgorithmHMACSHA256,
		SeedLength:  32,
		Derivation:  SeedDerivationLoopID,
		RecordToLog: true,
	}
}

// DeterministicPRNG provides reproducible random numbers.
// Per Section 2.4 - all randomness MUST be deterministic and logged.
type DeterministicPRNG struct {
	mu       sync.Mutex
	config   PRNGConfig
	seed     []byte
	counter  uint64
	loopID   string
	eventLog EventLog
}

// NewDeterministicPRNG creates a new PRNG with the given seed.
func NewDeterministicPRNG(config PRNGConfig, seed []byte, loopID string, log EventLog) (*DeterministicPRNG, error) {
	if len(seed) != config.SeedLength {
		return nil, fmt.Errorf("seed length %d does not match config %d", len(seed), config.SeedLength)
	}

	prng := &DeterministicPRNG{
		config:   config,
		seed:     make([]byte, len(seed)),
		counter:  0,
		loopID:   loopID,
		eventLog: log,
	}
	copy(prng.seed, seed)

	return prng, nil
}

// Seed returns the current seed (for logging).
func (p *DeterministicPRNG) Seed() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return hex.EncodeToString(p.seed)
}

// LoopID returns the loop ID.
func (p *DeterministicPRNG) LoopID() string {
	return p.loopID
}

// Uint64 returns a deterministic uint64.
func (p *DeterministicPRNG) Uint64() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()

	value := p.generate()

	// Record to event log if configured
	if p.config.RecordToLog && p.eventLog != nil {
		_, _ = p.eventLog.Append(context.Background(), &EventEnvelope{
			EventID:   fmt.Sprintf("prng-%s-%d", p.loopID, p.counter),
			EventType: "prng.generate",
			Payload: map[string]interface{}{
				"loop_id":   p.loopID,
				"counter":   p.counter,
				"algorithm": string(p.config.Algorithm),
			},
			Entropy: &EntropyContext{
				Seed:          p.Seed(),
				PRNGAlgorithm: string(p.config.Algorithm),
				LoopID:        p.loopID,
			},
		})
	}

	return value
}

// generate produces the next random value.
func (p *DeterministicPRNG) generate() uint64 {
	p.counter++

	switch p.config.Algorithm {
	case PRNGAlgorithmHMACSHA256:
		return p.hmacSHA256()
	default:
		return p.hmacSHA256()
	}
}

// hmacSHA256 generates random bytes using HMAC-SHA256.
func (p *DeterministicPRNG) hmacSHA256() uint64 {
	// HMAC(seed, counter)
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, p.counter)

	h := hmac.New(sha256.New, p.seed)
	h.Write(counterBytes)
	result := h.Sum(nil)

	// Take first 8 bytes as uint64
	return binary.BigEndian.Uint64(result[:8])
}

// Float64 returns a deterministic float64 in [0, 1).
func (p *DeterministicPRNG) Float64() float64 {
	return float64(p.Uint64()>>11) / (1 << 53)
}

// Intn returns a deterministic int in [0, n).
func (p *DeterministicPRNG) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(p.Uint64() % uint64(n)) //nolint:gosec // Safe modulo
}

// Bytes returns n deterministic random bytes.
func (p *DeterministicPRNG) Bytes(n int) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()

	result := make([]byte, n)
	for i := 0; i < n; i += 8 {
		p.counter++
		val := p.hmacSHA256()

		bytesToWrite := 8
		if n-i < 8 {
			bytesToWrite = n - i
		}

		valBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(valBytes, val)
		copy(result[i:i+bytesToWrite], valBytes[:bytesToWrite])
	}

	return result
}

// DeriveSeed derives a child seed from parent seed and derivation input.
func DeriveSeed(parentSeed []byte, derivationInput string) []byte {
	h := hmac.New(sha256.New, parentSeed)
	h.Write([]byte(derivationInput))
	return h.Sum(nil)
}

// SeedFromLoopID derives a seed from a root seed and loop ID.
func SeedFromLoopID(rootSeed []byte, loopID string) []byte {
	return DeriveSeed(rootSeed, "loop:"+loopID)
}
