package privacy

import "time"

// SecretShare represents one party's share of a secret value.
// Shares are created by Shamir's Secret Sharing over GF(256) and can only
// be combined when at least Threshold shares are present.
type SecretShare struct {
	// ShareID uniquely identifies this share within a split operation.
	ShareID string `json:"share_id"`

	// PartyID identifies the party holding this share.
	PartyID string `json:"party_id"`

	// Value is the share payload (one byte per secret byte).
	Value []byte `json:"value"`

	// Index is the evaluation point (1-based, never zero).
	Index int `json:"index"`

	// Threshold is the minimum number of shares needed to reconstruct.
	Threshold int `json:"threshold"`

	// Total is the total number of shares created.
	Total int `json:"total"`
}

// PrivateEvalRequest is a policy evaluation request with secret-shared inputs.
// The governance engine receives only shares; no single party sees the full input.
type PrivateEvalRequest struct {
	// RequestID uniquely identifies this evaluation request.
	RequestID string `json:"request_id"`

	// PolicyHash identifies which policy to evaluate (public metadata).
	PolicyHash string `json:"policy_hash"`

	// InputShares are the secret-shared fragments of the governed data.
	InputShares []SecretShare `json:"input_shares"`

	// PartyIDs lists all participating parties.
	PartyIDs []string `json:"party_ids"`

	// Threshold is the quorum size needed for reconstruction.
	Threshold int `json:"threshold"`

	// Timestamp records when the request was created.
	Timestamp time.Time `json:"timestamp"`
}

// PrivateEvalResult is the output of a private policy evaluation.
// The verdict is revealed, but the governed input remains hidden.
type PrivateEvalResult struct {
	// RequestID links this result to the originating request.
	RequestID string `json:"request_id"`

	// Verdict is the governance decision: ALLOW or DENY.
	Verdict string `json:"verdict"`

	// ProofHash is a SHA-256 proof that the evaluation was performed correctly
	// on the reconstructed input, without revealing the input itself.
	ProofHash string `json:"proof_hash"`

	// Parties lists the party IDs that contributed shares.
	Parties []string `json:"parties"`

	// Timestamp records when the evaluation completed.
	Timestamp time.Time `json:"timestamp"`

	// ContentHash is the SHA-256 of the canonical result body.
	ContentHash string `json:"content_hash"`
}

// DPConfig configures differential privacy parameters for compliance metrics.
type DPConfig struct {
	// Epsilon is the privacy budget. Lower values provide stronger privacy
	// guarantees but add more noise. Must be positive.
	Epsilon float64 `json:"epsilon"`

	// Delta is the failure probability bound. Must be in (0, 1).
	Delta float64 `json:"delta"`

	// Sensitivity is the maximum change any single record can cause in a query result.
	Sensitivity float64 `json:"sensitivity"`
}

// DPMetric is a differentially private metric value.
// The TrueValue field is never serialized to prevent accidental leakage.
type DPMetric struct {
	// MetricName identifies the metric.
	MetricName string `json:"metric_name"`

	// TrueValue is the actual value. Excluded from JSON serialization.
	TrueValue float64 `json:"-"`

	// NoisyValue is the differentially private value safe for release.
	NoisyValue float64 `json:"noisy_value"`

	// Epsilon records the privacy budget used for this metric.
	Epsilon float64 `json:"epsilon"`

	// Timestamp records when the metric was generated.
	Timestamp time.Time `json:"timestamp"`
}
