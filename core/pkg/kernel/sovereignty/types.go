package sovereignty

import "time"

// DecisionRecord represents a kernel-signed approval for an action.
// Schema: schemas/core/evidence_pack.schema.json
type DecisionRecord struct {
	DecisionID         string    `json:"decision_id"`
	PhenotypeHash      string    `json:"phenotype_hash"`
	RequirementSetHash string    `json:"requirement_set_hash"`
	Approvals          []string  `json:"approvals"`
	EffectDigest       string    `json:"effect_digest"`
	Expiry             time.Time `json:"expiry"`
	Signature          string    `json:"signature"` // Kernel signature
}

// AuthorizedExecutionIntent represents a specific instance of an allowed execution.
type AuthorizedExecutionIntent struct {
	ExecutionID  string    `json:"execution_id"`
	DecisionID   string    `json:"decision_id"`
	EffectDigest string    `json:"effect_digest"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Signature    string    `json:"signature"` // Kernel signature
}

// Receipt represents proof of execution.
type Receipt struct {
	ReceiptID      string    `json:"receipt_id"`
	ExecutionID    string    `json:"execution_id"`
	EffectDigest   string    `json:"effect_digest"`
	Timestamp      time.Time `json:"timestamp"`
	Status         string    `json:"status"` // "SUCCESS", "FAILURE"
	Payload        string    `json:"payload,omitempty"`
	IdempotencyKey string    `json:"idempotency_key"`
}
