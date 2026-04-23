package contracts

import "time"

// ApprovalReceipt represents a cryptographic approval signed by a human operator.
// This is the HITL (Human-in-the-Loop) bridge contract that binds a human's
// cryptographic identity to an execution intent.
//
// Security Properties:
//   - IntentHash links to the exact execution intent being approved
//   - Signature is Ed25519 over IntentHash (produced by WebCrypto API in browser)
//   - BiometricTier indicates the authentication strength
//   - Timestamp enables temporal ordering of approvals
type ApprovalReceipt struct {
	// IntentHash is the SHA-256 of the serialized AuthorizedExecutionIntent
	IntentHash string `json:"intent_hash"`

	// PlanHash is the hash of the execution plan
	PlanHash string `json:"plan_hash"`

	// PolicyHash is the hash of the enforced policy
	PolicyHash string `json:"policy_hash"`

	// Nonce is the unique execution nonce
	Nonce string `json:"nonce"`

	// ApproverID identifies the human operator
	ApproverID string `json:"approver_id"`

	// PublicKey is the Ed25519 public key of the approver (hex-encoded)
	PublicKey string `json:"public_key"`

	// Signature is the Ed25519 signature over IntentHash (hex-encoded)
	Signature string `json:"signature"`

	// Timestamp of when the approval was signed
	Timestamp time.Time `json:"timestamp"`

	// BiometricTier indicates the authentication method used
	// Values: "passkey", "webcrypto", "totp", "none"
	BiometricTier string `json:"biometric_tier"`

	// SessionID links this approval to a specific operator session
	SessionID string `json:"session_id,omitempty"`
}

// ApprovalStatus represents the current state of an approval request.
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "PENDING"
	ApprovalApproved ApprovalStatus = "APPROVED"
	ApprovalRejected ApprovalStatus = "REJECTED"
	ApprovalExpired  ApprovalStatus = "EXPIRED"
)

// ApprovalRequest represents a pending approval that the HITL bridge surfaces to operators.
type ApprovalRequest struct {
	RequestID  string         `json:"request_id"`
	IntentHash string         `json:"intent_hash"`
	IntentID   string         `json:"intent_id"`
	ToolName   string         `json:"tool_name"`
	RiskLevel  string         `json:"risk_level"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Status     ApprovalStatus `json:"status"`
	CreatedAt  time.Time      `json:"created_at"`
	ExpiresAt  time.Time      `json:"expires_at"`

	// Approval receipt, populated when status is APPROVED
	Receipt *ApprovalReceipt `json:"receipt,omitempty"`
}
