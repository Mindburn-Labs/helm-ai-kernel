// Package payments implements the AP2 (Agent Payments Protocol) for HELM A2A.
//
// AP2 enables agents to exchange payment requests, verify receipts, manage
// payment channels, and resolve disputes. All payment operations are
// fail-closed: invalid signatures, exceeded budgets, or unknown channels
// result in deterministic denial.
//
// Integration points:
//   - Budget gate: spend limit enforcement via budget.Enforcer
//   - HSM: receipt signing via hsm.Provider
//   - A2A: envelope-level payment feature negotiation (FeatureAgentPayments)
//
// Invariants:
//   - Receipts are signed and immutable once issued
//   - Payment channels have monotonically increasing sequence numbers
//   - Disputes reference a valid receipt ID and are non-repudiable
//   - All amounts are in cents (int64) to avoid floating-point drift
package payments

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// PaymentStatus tracks the lifecycle of a payment.
type PaymentStatus string

const (
	PaymentStatusPending   PaymentStatus = "PENDING"
	PaymentStatusCompleted PaymentStatus = "COMPLETED"
	PaymentStatusFailed    PaymentStatus = "FAILED"
	PaymentStatusDisputed  PaymentStatus = "DISPUTED"
	PaymentStatusRefunded  PaymentStatus = "REFUNDED"
)

// PaymentMethod identifies the settlement mechanism.
type PaymentMethod string

const (
	PaymentMethodBudget   PaymentMethod = "BUDGET"    // Internal budget gate deduction
	PaymentMethodEscrow   PaymentMethod = "ESCROW"    // Held in escrow until confirmed
	PaymentMethodPrepaid  PaymentMethod = "PREPAID"   // Pre-funded channel balance
	PaymentMethodOnDemand PaymentMethod = "ON_DEMAND" // Charged per-request
)

// DisputeReason classifies the grounds for a payment dispute.
type DisputeReason string

const (
	DisputeServiceNotRendered DisputeReason = "SERVICE_NOT_RENDERED"
	DisputeAmountIncorrect    DisputeReason = "AMOUNT_INCORRECT"
	DisputeUnauthorized       DisputeReason = "UNAUTHORIZED"
	DisputeDuplicate          DisputeReason = "DUPLICATE"
	DisputeQualityDeficient   DisputeReason = "QUALITY_DEFICIENT"
)

// DisputeStatus tracks the lifecycle of a dispute.
type DisputeStatus string

const (
	DisputeStatusOpen      DisputeStatus = "OPEN"
	DisputeStatusResolved  DisputeStatus = "RESOLVED"
	DisputeStatusRejected  DisputeStatus = "REJECTED"
	DisputeStatusEscalated DisputeStatus = "ESCALATED"
)

// PaymentRequest is an AP2 message requesting payment from one agent to another.
type PaymentRequest struct {
	RequestID      string            `json:"request_id"`
	FromAgentID    string            `json:"from_agent_id"` // Requestor (payee)
	ToAgentID      string            `json:"to_agent_id"`   // Payer
	ChannelID      string            `json:"channel_id"`    // Payment channel reference
	AmountCents    int64             `json:"amount_cents"`  // Amount in cents
	Currency       string            `json:"currency"`      // ISO 4217 (e.g., "USD")
	Description    string            `json:"description"`   // Human-readable reason
	Method         PaymentMethod     `json:"method"`
	IdempotencyKey string            `json:"idempotency_key"` // Prevents duplicate charges
	EnvelopeID     string            `json:"envelope_id"`     // A2A envelope reference
	CreatedAt      time.Time         `json:"created_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// Hash returns a deterministic SHA-256 hash of the payment request.
func (pr *PaymentRequest) Hash() string {
	hashable := struct {
		RequestID      string `json:"request_id"`
		FromAgentID    string `json:"from_agent_id"`
		ToAgentID      string `json:"to_agent_id"`
		ChannelID      string `json:"channel_id"`
		AmountCents    int64  `json:"amount_cents"`
		Currency       string `json:"currency"`
		IdempotencyKey string `json:"idempotency_key"`
	}{
		RequestID:      pr.RequestID,
		FromAgentID:    pr.FromAgentID,
		ToAgentID:      pr.ToAgentID,
		ChannelID:      pr.ChannelID,
		AmountCents:    pr.AmountCents,
		Currency:       pr.Currency,
		IdempotencyKey: pr.IdempotencyKey,
	}
	data, _ := json.Marshal(hashable)
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// PaymentReceipt is the signed proof that a payment was processed.
type PaymentReceipt struct {
	ReceiptID       string            `json:"receipt_id"`
	RequestID       string            `json:"request_id"` // Links to PaymentRequest
	ChannelID       string            `json:"channel_id"`
	FromAgentID     string            `json:"from_agent_id"` // Payee
	ToAgentID       string            `json:"to_agent_id"`   // Payer
	AmountCents     int64             `json:"amount_cents"`
	Currency        string            `json:"currency"`
	Status          PaymentStatus     `json:"status"`
	Method          PaymentMethod     `json:"method"`
	SequenceNum     int64             `json:"sequence_num"`  // Monotonic within channel
	RequestHash     string            `json:"request_hash"`  // Hash of the original request
	SignatureKID    string            `json:"signature_kid"` // Signing key ID
	SignatureAlg    string            `json:"signature_alg"` // Signing algorithm
	SignatureVal    []byte            `json:"signature_val"` // Raw signature bytes
	IssuedAt        time.Time         `json:"issued_at"`
	BudgetReceiptID string            `json:"budget_receipt_id,omitempty"` // Links to budget enforcement receipt
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// SignableContent returns the canonical bytes to sign for this receipt.
func (r *PaymentReceipt) SignableContent() []byte {
	signable := struct {
		ReceiptID   string `json:"receipt_id"`
		RequestID   string `json:"request_id"`
		ChannelID   string `json:"channel_id"`
		FromAgentID string `json:"from_agent_id"`
		ToAgentID   string `json:"to_agent_id"`
		AmountCents int64  `json:"amount_cents"`
		Currency    string `json:"currency"`
		Status      string `json:"status"`
		SequenceNum int64  `json:"sequence_num"`
		RequestHash string `json:"request_hash"`
	}{
		ReceiptID:   r.ReceiptID,
		RequestID:   r.RequestID,
		ChannelID:   r.ChannelID,
		FromAgentID: r.FromAgentID,
		ToAgentID:   r.ToAgentID,
		AmountCents: r.AmountCents,
		Currency:    r.Currency,
		Status:      string(r.Status),
		SequenceNum: r.SequenceNum,
		RequestHash: r.RequestHash,
	}
	data, _ := json.Marshal(signable)
	return data
}

// Hash returns a deterministic SHA-256 hash of the receipt content.
func (r *PaymentReceipt) Hash() string {
	h := sha256.Sum256(r.SignableContent())
	return "sha256:" + hex.EncodeToString(h[:])
}

// PaymentDispute challenges a specific payment receipt.
type PaymentDispute struct {
	DisputeID   string        `json:"dispute_id"`
	ReceiptID   string        `json:"receipt_id"` // The disputed receipt
	ChannelID   string        `json:"channel_id"`
	DisputerID  string        `json:"disputer_id"` // Agent raising the dispute
	Reason      DisputeReason `json:"reason"`
	Description string        `json:"description"` // Detailed explanation
	Evidence    string        `json:"evidence"`    // Supporting evidence hash
	Status      DisputeStatus `json:"status"`
	Resolution  string        `json:"resolution,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	ResolvedAt  *time.Time    `json:"resolved_at,omitempty"`
}

// PaymentChannel represents a bidirectional payment channel between two agents.
// Channels track cumulative state to enable efficient micro-payments without
// per-transaction overhead.
type PaymentChannel struct {
	ChannelID      string        `json:"channel_id"`
	AgentA         string        `json:"agent_a"` // First party
	AgentB         string        `json:"agent_b"` // Second party
	Method         PaymentMethod `json:"method"`
	Currency       string        `json:"currency"`
	BalanceCentsA  int64         `json:"balance_cents_a"` // Net balance owed to A
	BalanceCentsB  int64         `json:"balance_cents_b"` // Net balance owed to B
	SequenceNum    int64         `json:"sequence_num"`    // Last sequence number used
	SpendLimitA    int64         `json:"spend_limit_a"`   // Max A can spend per settlement
	SpendLimitB    int64         `json:"spend_limit_b"`   // Max B can spend per settlement
	TotalVolumeA   int64         `json:"total_volume_a"`  // Cumulative A -> B
	TotalVolumeB   int64         `json:"total_volume_b"`  // Cumulative B -> A
	IsOpen         bool          `json:"is_open"`
	OpenedAt       time.Time     `json:"opened_at"`
	ClosedAt       *time.Time    `json:"closed_at,omitempty"`
	LastActivityAt time.Time     `json:"last_activity_at"`
}

// NextSequence increments and returns the next sequence number.
func (ch *PaymentChannel) NextSequence() int64 {
	ch.SequenceNum++
	return ch.SequenceNum
}

// NetBalance returns the net settlement amount.
// Positive means A is owed; negative means B is owed.
func (ch *PaymentChannel) NetBalance() int64 {
	return ch.BalanceCentsA - ch.BalanceCentsB
}

// ChannelSummary provides a read-only snapshot of channel state.
type ChannelSummary struct {
	ChannelID   string `json:"channel_id"`
	AgentA      string `json:"agent_a"`
	AgentB      string `json:"agent_b"`
	NetBalance  int64  `json:"net_balance"`
	SequenceNum int64  `json:"sequence_num"`
	TotalVolume int64  `json:"total_volume"`
	IsOpen      bool   `json:"is_open"`
}

// Summarize returns a read-only snapshot of the channel.
func (ch *PaymentChannel) Summarize() *ChannelSummary {
	return &ChannelSummary{
		ChannelID:   ch.ChannelID,
		AgentA:      ch.AgentA,
		AgentB:      ch.AgentB,
		NetBalance:  ch.NetBalance(),
		SequenceNum: ch.SequenceNum,
		TotalVolume: ch.TotalVolumeA + ch.TotalVolumeB,
		IsOpen:      ch.IsOpen,
	}
}
