package privacy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// GF(256) arithmetic tables for Shamir's Secret Sharing.
// Addition in GF(256) is XOR. Multiplication uses log/exp tables
// with generator 2 and irreducible polynomial 0x11D (x^8 + x^4 + x^3 + x^2 + 1).
var (
	gfExp [512]byte // exp table (doubled for wraparound)
	gfLog [256]byte // log table
)

func init() {
	// Build GF(256) log/exp tables using generator 2
	// with irreducible polynomial 0x11D (x^8 + x^4 + x^3 + x^2 + 1).
	// Generator 2 is a primitive element under this polynomial,
	// meaning 2^i cycles through all 255 non-zero elements of GF(256).
	var x uint16 = 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfExp[i+255] = byte(x) // wraparound copy for easy modular indexing
		gfLog[byte(x)] = byte(i)
		// Multiply by generator 2 (left shift), reduce by polynomial if needed.
		x <<= 1
		if x >= 256 {
			x ^= 0x11D
		}
	}
	// gfLog[0] is unused (log(0) is undefined), left as 0.
	// gfLog[1] = 0 (correct: 2^0 = 1).
}

// gfMul multiplies two GF(256) elements.
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// gfInv returns the multiplicative inverse of a in GF(256).
func gfInv(a byte) byte {
	if a == 0 {
		return 0 // undefined, but safe fallback
	}
	return gfExp[255-int(gfLog[a])]
}

// gfDiv divides a by b in GF(256).
func gfDiv(a, b byte) byte {
	if b == 0 {
		return 0 // undefined, but safe fallback
	}
	if a == 0 {
		return 0
	}
	return gfMul(a, gfInv(b))
}

// SecretSharer splits and reconstructs secrets using Shamir's Secret Sharing
// over GF(256). Each byte of the secret is independently split using a
// random polynomial of degree (threshold - 1).
type SecretSharer struct {
	threshold int
	total     int
}

// NewSecretSharer creates a new secret sharer.
// threshold is the minimum number of shares needed to reconstruct (must be >= 2).
// total is the number of shares to generate (must be >= threshold).
func NewSecretSharer(threshold, total int) (*SecretSharer, error) {
	if threshold < 2 {
		return nil, errors.New("privacy: threshold must be at least 2")
	}
	if total < 2 {
		return nil, errors.New("privacy: total must be at least 2")
	}
	if threshold > total {
		return nil, errors.New("privacy: threshold must not exceed total")
	}
	if total > 255 {
		return nil, errors.New("privacy: total must not exceed 255 (GF(256) constraint)")
	}
	return &SecretSharer{threshold: threshold, total: total}, nil
}

// Split divides a secret into shares using Shamir's Secret Sharing.
// Each byte of the secret is independently shared using a random polynomial
// of degree (threshold - 1) evaluated at points 1..total over GF(256).
func (s *SecretSharer) Split(secret []byte) ([]SecretShare, error) {
	if len(secret) == 0 {
		return nil, errors.New("privacy: secret must not be empty")
	}

	shares := make([]SecretShare, s.total)
	for i := range shares {
		shares[i] = SecretShare{
			ShareID:   generateShareID(),
			Index:     i + 1, // 1-based
			Threshold: s.threshold,
			Total:     s.total,
			Value:     make([]byte, len(secret)),
		}
	}

	// For each byte of the secret, generate a random polynomial and evaluate it.
	coeffs := make([]byte, s.threshold)
	for byteIdx := 0; byteIdx < len(secret); byteIdx++ {
		// coeffs[0] = secret byte (the constant term)
		coeffs[0] = secret[byteIdx]

		// coeffs[1..threshold-1] = random
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, fmt.Errorf("privacy: random generation failed: %w", err)
		}

		// Evaluate polynomial at each point x = 1..total
		for i := 0; i < s.total; i++ {
			x := byte(i + 1)
			shares[i].Value[byteIdx] = evalPolynomial(coeffs, x)
		}
	}

	return shares, nil
}

// Reconstruct recovers the secret from at least threshold shares using
// Lagrange interpolation over GF(256).
func (s *SecretSharer) Reconstruct(shares []SecretShare) ([]byte, error) {
	if len(shares) < s.threshold {
		return nil, fmt.Errorf("privacy: need at least %d shares, got %d", s.threshold, len(shares))
	}

	if len(shares) == 0 {
		return nil, errors.New("privacy: no shares provided")
	}

	secretLen := len(shares[0].Value)
	for _, sh := range shares {
		if len(sh.Value) != secretLen {
			return nil, errors.New("privacy: all shares must have the same length")
		}
	}

	// Use only the first threshold shares.
	used := shares[:s.threshold]

	// Extract the x-coordinates.
	xs := make([]byte, s.threshold)
	for i, sh := range used {
		xs[i] = byte(sh.Index)
	}

	secret := make([]byte, secretLen)
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		// Lagrange interpolation at x=0 to recover the constant term (the secret byte).
		var result byte
		for i := 0; i < s.threshold; i++ {
			// Compute Lagrange basis polynomial L_i(0)
			var num byte = 1 // product of (0 - x_j) = product of x_j in GF(256)
			var den byte = 1 // product of (x_i - x_j)
			for j := 0; j < s.threshold; j++ {
				if i == j {
					continue
				}
				num = gfMul(num, xs[j])       // 0 XOR x_j = x_j
				den = gfMul(den, xs[i]^xs[j]) // x_i - x_j = x_i XOR x_j in GF(256)
			}
			lagrange := gfDiv(num, den)
			result ^= gfMul(used[i].Value[byteIdx], lagrange)
		}
		secret[byteIdx] = result
	}

	return secret, nil
}

// evalPolynomial evaluates a polynomial with the given coefficients at point x over GF(256).
// coeffs[0] is the constant term, coeffs[1] is the x coefficient, etc.
// Uses Horner's method for efficiency.
func evalPolynomial(coeffs []byte, x byte) byte {
	// Horner's method: result = c[n-1]; for i = n-2..0: result = result*x + c[i]
	// In GF(256): + is XOR, * is gfMul.
	result := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = gfMul(result, x) ^ coeffs[i]
	}
	return result
}

// generateShareID produces a random hex identifier for a share.
func generateShareID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// PrivateEvaluator performs policy evaluation on secret-shared data.
// The evaluator reconstructs the input only transiently, evaluates the policy,
// then zeros the reconstructed data from memory.
type PrivateEvaluator struct {
	sharer *SecretSharer
	clock  func() time.Time
}

// NewPrivateEvaluator creates a new private evaluator.
// threshold and totalParties configure the underlying secret sharing scheme.
func NewPrivateEvaluator(threshold, totalParties int) (*PrivateEvaluator, error) {
	sharer, err := NewSecretSharer(threshold, totalParties)
	if err != nil {
		return nil, fmt.Errorf("privacy: failed to create evaluator: %w", err)
	}
	return &PrivateEvaluator{
		sharer: sharer,
		clock:  time.Now,
	}, nil
}

// WithClock overrides the clock for deterministic testing.
func (e *PrivateEvaluator) WithClock(clock func() time.Time) *PrivateEvaluator {
	e.clock = clock
	return e
}

// EvaluatePrivately performs a governance decision on secret-shared input.
//
// The evaluator never persists the full input. The reconstruction is transient:
// the input is recovered from shares, the policy function is evaluated, and
// the reconstructed bytes are zeroed from memory before returning.
//
// The returned result contains the verdict (ALLOW/DENY) and a proof hash
// that binds the policy, input, and verdict together for auditability.
func (e *PrivateEvaluator) EvaluatePrivately(req PrivateEvalRequest, policyEvalFn func(input []byte) (string, error)) (*PrivateEvalResult, error) {
	if len(req.InputShares) < req.Threshold {
		return nil, fmt.Errorf("privacy: need at least %d shares, got %d", req.Threshold, len(req.InputShares))
	}

	// Step 1: Reconstruct input from shares.
	input, err := e.sharer.Reconstruct(req.InputShares)
	if err != nil {
		return nil, fmt.Errorf("privacy: reconstruction failed: %w", err)
	}

	// Step 2: Evaluate the policy function on the reconstructed input.
	verdict, err := policyEvalFn(input)
	if err != nil {
		zeroBytes(input)
		return nil, fmt.Errorf("privacy: policy evaluation failed: %w", err)
	}

	// Step 3: Generate proof hash binding policy + input + verdict.
	proofHash := computeProofHash(req.PolicyHash, input, verdict)

	// Step 4: Zero the reconstructed input from memory.
	zeroBytes(input)

	// Step 5: Collect participating party IDs.
	parties := make([]string, 0, len(req.InputShares))
	seen := make(map[string]bool, len(req.InputShares))
	for _, share := range req.InputShares {
		if share.PartyID != "" && !seen[share.PartyID] {
			parties = append(parties, share.PartyID)
			seen[share.PartyID] = true
		}
	}

	now := e.clock()

	result := &PrivateEvalResult{
		RequestID: req.RequestID,
		Verdict:   verdict,
		ProofHash: proofHash,
		Parties:   parties,
		Timestamp: now,
	}

	// Step 6: Compute content hash over the canonical result.
	contentHash := computeContentHash(result)
	result.ContentHash = contentHash

	return result, nil
}

// computeProofHash produces a SHA-256 hash binding the policy, input, and verdict.
// This proves the evaluation was performed on a specific input under a specific
// policy, without the verifier needing to see the input.
func computeProofHash(policyHash string, input []byte, verdict string) string {
	h := sha256.New()
	h.Write([]byte(policyHash))
	h.Write(input)
	h.Write([]byte(verdict))
	return hex.EncodeToString(h.Sum(nil))
}

// computeContentHash computes SHA-256 over the canonical fields of a result.
func computeContentHash(r *PrivateEvalResult) string {
	h := sha256.New()
	h.Write([]byte(r.RequestID))
	h.Write([]byte(r.Verdict))
	h.Write([]byte(r.ProofHash))
	for _, p := range r.Parties {
		h.Write([]byte(p))
	}
	h.Write([]byte(r.Timestamp.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))
}

// zeroBytes overwrites a byte slice with zeros to prevent secret leakage.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
