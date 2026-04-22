package keystore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// RotationEventType identifies the kind of key rotation action.
type RotationEventType string

const (
	RotationEventGenerate RotationEventType = "KEY_GENERATE"
	RotationEventImport   RotationEventType = "KEY_IMPORT"
	RotationEventRevoke   RotationEventType = "KEY_REVOKE"
	RotationEventExpire   RotationEventType = "KEY_EXPIRE"
)

// RotationEvent records a key lifecycle action.
// Each event is signed by the currently active key to prove authorization.
type RotationEvent struct {
	EventID       string            `json:"event_id"`
	EventType     RotationEventType `json:"event_type"`
	KID           string            `json:"kid"`
	Algorithm     string            `json:"algorithm"`
	Purpose       KeyPurpose        `json:"purpose"`
	Timestamp     time.Time         `json:"timestamp"`
	AuthorizedBy  string            `json:"authorized_by"`   // KID of the authorizing key
	PublicKeyHash string            `json:"public_key_hash"` // SHA256 of the new public key
	Reason        string            `json:"reason,omitempty"`
}

// Hash computes a deterministic hash of the rotation event (excluding signatures).
func (e *RotationEvent) Hash() (string, error) {
	hashable := struct {
		EventID       string            `json:"event_id"`
		EventType     RotationEventType `json:"event_type"`
		KID           string            `json:"kid"`
		Algorithm     string            `json:"algorithm"`
		Purpose       KeyPurpose        `json:"purpose"`
		Timestamp     time.Time         `json:"timestamp"`
		AuthorizedBy  string            `json:"authorized_by"`
		PublicKeyHash string            `json:"public_key_hash"`
		Reason        string            `json:"reason,omitempty"`
	}{
		EventID:       e.EventID,
		EventType:     e.EventType,
		KID:           e.KID,
		Algorithm:     e.Algorithm,
		Purpose:       e.Purpose,
		Timestamp:     e.Timestamp,
		AuthorizedBy:  e.AuthorizedBy,
		PublicKeyHash: e.PublicKeyHash,
		Reason:        e.Reason,
	}
	data, err := json.Marshal(hashable)
	if err != nil {
		return "", fmt.Errorf("failed to marshal rotation event: %w", err)
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// RotationReceipt proves that a key rotation was authorized.
type RotationReceipt struct {
	Event         RotationEvent `json:"event"`
	EventHash     string        `json:"event_hash"`
	AuthorizerSig string        `json:"authorizer_signature"` // Signature by authorized_by key
	AuthorizerKID string        `json:"authorizer_kid"`
	LamportClock  uint64        `json:"lamport_clock"`
}

// RotationPlan describes a requested key rotation with pre/post verification.
type RotationPlan struct {
	PlanID      string         `json:"plan_id"`
	CreatedAt   time.Time      `json:"created_at"`
	NewKID      string         `json:"new_kid"`
	ReplacesKID string         `json:"replaces_kid"`
	Algorithm   string         `json:"algorithm"`
	Purpose     KeyPurpose     `json:"purpose"`
	Reason      string         `json:"reason"`
	Steps       []RotationStep `json:"steps"`
}

// RotationStep is a single step in a rotation plan.
type RotationStep struct {
	StepID      string     `json:"step_id"`
	Action      string     `json:"action"` // "generate", "activate", "verify", "revoke_old"
	Status      string     `json:"status"` // "pending", "complete", "failed"
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// RotationExecutor performs key rotations and emits receipts.
type RotationExecutor struct {
	provider *MemoryKeyProvider
	clock    func() time.Time
}

// NewRotationExecutor creates a new rotation executor.
func NewRotationExecutor(provider *MemoryKeyProvider) *RotationExecutor {
	return &RotationExecutor{
		provider: provider,
		clock:    time.Now,
	}
}

// WithClock overrides the clock (for testing).
func (r *RotationExecutor) WithClock(clock func() time.Time) *RotationExecutor {
	r.clock = clock
	return r
}

// Rotate generates a new key, signs the rotation event with the old key, and revokes the old key.
// Returns the rotation receipt proving authorization.
func (r *RotationExecutor) Rotate(plan *RotationPlan) (*RotationReceipt, error) {
	now := r.clock()

	// 1. Get the current active signer (the authorizer)
	authorizer, err := r.provider.ActiveSigner()
	if err != nil {
		return nil, fmt.Errorf("no active key to authorize rotation: %w", err)
	}

	// 2. Generate the new key
	newSigner, err := r.provider.GenerateKey(plan.NewKID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key: %w", err)
	}

	// 3. Create the rotation event
	pubKeyHash := sha256.Sum256(newSigner.PublicKey())
	event := RotationEvent{
		EventID:       fmt.Sprintf("rot-%s-%d", plan.NewKID, now.UnixNano()),
		EventType:     RotationEventGenerate,
		KID:           plan.NewKID,
		Algorithm:     plan.Algorithm,
		Purpose:       plan.Purpose,
		Timestamp:     now.UTC(),
		AuthorizedBy:  authorizer.KID(),
		PublicKeyHash: "sha256:" + hex.EncodeToString(pubKeyHash[:]),
		Reason:        plan.Reason,
	}

	// 4. Hash and sign the event with the OLD key
	eventHash, err := event.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to hash rotation event: %w", err)
	}

	sig, err := authorizer.Sign([]byte(eventHash))
	if err != nil {
		return nil, fmt.Errorf("failed to sign rotation event: %w", err)
	}

	// 5. Revoke the old key if specified
	if plan.ReplacesKID != "" {
		if err := r.provider.RevokeKey(plan.ReplacesKID); err != nil {
			return nil, fmt.Errorf("failed to revoke old key %s: %w", plan.ReplacesKID, err)
		}
	}

	receipt := &RotationReceipt{
		Event:         event,
		EventHash:     eventHash,
		AuthorizerSig: string(sig),
		AuthorizerKID: authorizer.KID(),
	}

	return receipt, nil
}
