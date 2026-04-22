// Package kernel provides effect boundary enforcement.
// Per Section 1.4 - Effect Interception Boundary
package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// EffectType defines canonical effect types per Section 8.
type EffectType string

const (
	EffectTypeDataWrite        EffectType = "DATA_WRITE"
	EffectTypeFundsTransfer    EffectType = "FUNDS_TRANSFER"
	EffectTypePermissionChange EffectType = "PERMISSION_CHANGE"
	EffectTypeDeploy           EffectType = "DEPLOY"
	EffectTypeNotify           EffectType = "NOTIFY"
	EffectTypeModuleInstall    EffectType = "MODULE_INSTALL"
	EffectTypeConfigChange     EffectType = "CONFIG_CHANGE"
	EffectTypeAuditLog         EffectType = "AUDIT_LOG"
	EffectTypeExternalAPICall  EffectType = "EXTERNAL_API_CALL"
)

// EffectSubject represents the actor submitting an effect.
type EffectSubject struct {
	SubjectID      string `json:"subject_id"`
	SubjectType    string `json:"subject_type"` // human, module, control_loop, external_system
	SessionID      string `json:"session_id,omitempty"`
	AttestationRef string `json:"attestation_ref,omitempty"`
}

// EffectPayload contains the effect data.
type EffectPayload struct {
	PayloadHash string                 `json:"payload_hash"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// IdempotencyConfig defines idempotency enforcement.
type IdempotencyConfig struct {
	Key           string `json:"key"`
	KeyDerivation string `json:"key_derivation"` // client_provided, content_hash, effect_id
	WindowSeconds int    `json:"window_seconds,omitempty"`
}

// EffectContext provides contextual information.
type EffectContext struct {
	ModeID        string `json:"mode_id,omitempty"`
	LoopID        string `json:"loop_id,omitempty"`
	PhenotypeHash string `json:"phenotype_hash,omitempty"`
	EnvironmentID string `json:"environment_id,omitempty"`
}

// EffectRequest represents an effect submitted to the kernel boundary.
// Per Section 1.4 - Effect Interception Boundary
type EffectRequest struct {
	EffectID    string             `json:"effect_id"`
	EffectType  EffectType         `json:"effect_type"`
	SubmittedAt time.Time          `json:"submitted_at"`
	Subject     EffectSubject      `json:"subject"`
	Payload     EffectPayload      `json:"payload"`
	Idempotency *IdempotencyConfig `json:"idempotency,omitempty"`
	Context     *EffectContext     `json:"context,omitempty"`
}

// EffectLifecycle tracks effect state transitions.
type EffectLifecycle struct {
	State          string    `json:"state"` // pending, approved, denied, executing, completed, failed, compensated
	PDPDecisionID  string    `json:"pdp_decision_id,omitempty"`
	ExecutedAt     time.Time `json:"executed_at,omitempty"`
	CompletedAt    time.Time `json:"completed_at,omitempty"`
	EvidencePackID string    `json:"evidence_pack_id,omitempty"`
}

// EffectBoundary enforces the effect interception boundary.
// All effects MUST pass through this boundary before execution.
type EffectBoundary interface {
	// Submit submits an effect request for policy evaluation.
	// Returns the effect ID and initial lifecycle state.
	Submit(ctx context.Context, req *EffectRequest) (*EffectLifecycle, error)

	// Approve marks an effect as approved by the PDP.
	Approve(ctx context.Context, effectID, decisionID string) error

	// Deny marks an effect as denied by the PDP.
	Deny(ctx context.Context, effectID, decisionID, reason string) error

	// Execute marks an effect as executing.
	Execute(ctx context.Context, effectID string) error

	// Complete marks an effect as completed.
	Complete(ctx context.Context, effectID, evidencePackID string) error

	// GetLifecycle returns the current lifecycle state.
	GetLifecycle(ctx context.Context, effectID string) (*EffectLifecycle, error)

	// CheckIdempotency checks if an effect with this key was already processed.
	CheckIdempotency(ctx context.Context, key string) (bool, string, error)
}

// PDPEvaluator is the interface for the Policy Decision Point.
type PDPEvaluator interface {
	Evaluate(ctx context.Context, req *EffectRequest) (decision string, decisionID string, err error)
}

// InMemoryEffectBoundary is a reference implementation.
type InMemoryEffectBoundary struct {
	effects        map[string]*EffectRequest
	lifecycles     map[string]*EffectLifecycle
	idempotencyLog map[string]string // key -> effectID
	pdp            PDPEvaluator
	eventLog       EventLog
}

// NewInMemoryEffectBoundary creates a new effect boundary.
func NewInMemoryEffectBoundary(pdp PDPEvaluator, log EventLog) *InMemoryEffectBoundary {
	return &InMemoryEffectBoundary{
		effects:        make(map[string]*EffectRequest),
		lifecycles:     make(map[string]*EffectLifecycle),
		idempotencyLog: make(map[string]string),
		pdp:            pdp,
		eventLog:       log,
	}
}

// Submit submits an effect for policy evaluation.
//
//nolint:gocognit // complexity acceptable
func (b *InMemoryEffectBoundary) Submit(ctx context.Context, req *EffectRequest) (*EffectLifecycle, error) {
	// Validate required fields
	if req.EffectType == "" {
		return nil, fmt.Errorf("effect_type is required")
	}
	if req.Subject.SubjectID == "" {
		return nil, fmt.Errorf("subject.subject_id is required")
	}

	// Generate effect ID if not provided
	if req.EffectID == "" {
		req.EffectID = uuid.New().String()
	}

	// Set submission timestamp
	if req.SubmittedAt.IsZero() {
		req.SubmittedAt = time.Now().UTC()
	}

	// Compute payload hash if not provided
	if req.Payload.PayloadHash == "" && req.Payload.Data != nil {
		hash, err := computePayloadHash(req.Payload.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to compute payload hash: %w", err)
		}
		req.Payload.PayloadHash = hash
	}

	// Handle idempotency
	if req.Idempotency != nil && req.Idempotency.Key != "" {
		if existingID, exists := b.idempotencyLog[req.Idempotency.Key]; exists {
			// Return existing lifecycle
			return b.lifecycles[existingID], nil
		}
	}

	// Store effect
	b.effects[req.EffectID] = req

	// Initialize lifecycle
	lifecycle := &EffectLifecycle{
		State: "pending",
	}
	b.lifecycles[req.EffectID] = lifecycle

	// Record idempotency key
	if req.Idempotency != nil && req.Idempotency.Key != "" {
		b.idempotencyLog[req.Idempotency.Key] = req.EffectID
	}

	// Log event
	if b.eventLog != nil {
		_, _ = b.eventLog.Append(ctx, &EventEnvelope{
			EventID:    uuid.New().String(),
			EventType:  "effect.submitted",
			ObservedAt: req.SubmittedAt,
			ReceivedAt: time.Now().UTC(),
			Payload: map[string]interface{}{
				"effect_id":    req.EffectID,
				"effect_type":  string(req.EffectType),
				"subject_id":   req.Subject.SubjectID,
				"payload_hash": req.Payload.PayloadHash,
			},
		})
	}

	// Invoke PDP if available
	if b.pdp != nil {
		decision, decisionID, err := b.pdp.Evaluate(ctx, req)
		if err != nil {
			lifecycle.State = "denied"
			return lifecycle, fmt.Errorf("PDP evaluation failed: %w", err)
		}

		lifecycle.PDPDecisionID = decisionID
		if decision == "ALLOW" {
			lifecycle.State = "approved"
		} else {
			lifecycle.State = "denied"
		}
	}

	return lifecycle, nil
}

// Approve marks an effect as approved.
func (b *InMemoryEffectBoundary) Approve(ctx context.Context, effectID, decisionID string) error {
	lifecycle, exists := b.lifecycles[effectID]
	if !exists {
		return fmt.Errorf("effect not found: %s", effectID)
	}
	lifecycle.State = "approved"
	lifecycle.PDPDecisionID = decisionID
	return nil
}

// Deny marks an effect as denied.
func (b *InMemoryEffectBoundary) Deny(ctx context.Context, effectID, decisionID, reason string) error {
	lifecycle, exists := b.lifecycles[effectID]
	if !exists {
		return fmt.Errorf("effect not found: %s", effectID)
	}
	lifecycle.State = "denied"
	lifecycle.PDPDecisionID = decisionID
	return nil
}

// Execute marks an effect as executing.
func (b *InMemoryEffectBoundary) Execute(ctx context.Context, effectID string) error {
	lifecycle, exists := b.lifecycles[effectID]
	if !exists {
		return fmt.Errorf("effect not found: %s", effectID)
	}
	if lifecycle.State != "approved" {
		return fmt.Errorf("cannot execute effect in state: %s", lifecycle.State)
	}
	lifecycle.State = "executing"
	lifecycle.ExecutedAt = time.Now().UTC()
	return nil
}

// Complete marks an effect as completed.
func (b *InMemoryEffectBoundary) Complete(ctx context.Context, effectID, evidencePackID string) error {
	lifecycle, exists := b.lifecycles[effectID]
	if !exists {
		return fmt.Errorf("effect not found: %s", effectID)
	}
	lifecycle.State = "completed"
	lifecycle.CompletedAt = time.Now().UTC()
	lifecycle.EvidencePackID = evidencePackID
	return nil
}

// GetLifecycle returns the current lifecycle state.
func (b *InMemoryEffectBoundary) GetLifecycle(ctx context.Context, effectID string) (*EffectLifecycle, error) {
	lifecycle, exists := b.lifecycles[effectID]
	if !exists {
		return nil, fmt.Errorf("effect not found: %s", effectID)
	}
	return lifecycle, nil
}

// CheckIdempotency checks if an effect with this key was already processed.
func (b *InMemoryEffectBoundary) CheckIdempotency(ctx context.Context, key string) (bool, string, error) {
	effectID, exists := b.idempotencyLog[key]
	return exists, effectID, nil
}

// computePayloadHash computes SHA-256 of payload data.
func computePayloadHash(data map[string]interface{}) (string, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}
