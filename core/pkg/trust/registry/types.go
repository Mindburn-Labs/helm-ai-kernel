// Package registry provides an event-sourced, lamport-indexed Trust Registry for HELM.
//
// The Trust Registry is the substrate for all identity, key, and policy trust decisions.
// It is append-only: trust state is derived deterministically by folding events.
// Snapshots at any lamport height produce identical bytes on any node.
package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// EventType identifies the kind of trust event.
type EventType string

const (
	EventDIDRegister    EventType = "DID_REGISTER"
	EventDIDDeactivate  EventType = "DID_DEACTIVATE"
	EventKeyPublish     EventType = "KEY_PUBLISH"
	EventKeyRevoke      EventType = "KEY_REVOKE"
	EventKeyRotate      EventType = "KEY_ROTATE"
	EventPolicyActivate EventType = "POLICY_ACTIVATE"
	EventPolicyRevoke   EventType = "POLICY_REVOKE"
	EventRoleGrant      EventType = "ROLE_GRANT"
	EventRoleRevoke     EventType = "ROLE_REVOKE"
	EventTenantRegister    EventType = "TENANT_REGISTER"
	EventTenantSuspend     EventType = "TENANT_SUSPEND"
	EventTrustScoreUpdate  EventType = "TRUST_SCORE_UPDATE"
	EventOrgTrustEstablish EventType = "ORG_TRUST_ESTABLISH"
	EventOrgTrustRevoke    EventType = "ORG_TRUST_REVOKE"
)

// TrustEvent is the atomic unit of trust state change.
// Events are append-only and form a hash chain.
type TrustEvent struct {
	ID          string          `json:"id"`
	Lamport     uint64          `json:"lamport"`
	EventType   EventType       `json:"event_type"`
	SubjectID   string          `json:"subject_id"`   // DID, KID, PolicyID, etc.
	SubjectType string          `json:"subject_type"` // "did", "key", "policy", "role", "tenant"
	Payload     json.RawMessage `json:"payload"`
	Hash        string          `json:"hash"`       // SHA256 of canonical event bytes
	PrevHash    string          `json:"prev_hash"`  // Hash of previous event (chain link)
	AuthorKID   string          `json:"author_kid"` // KID that authored this event
	AuthorSig   string          `json:"author_sig"` // Signature by author key
	CreatedAt   time.Time       `json:"created_at"`
}

// ComputeHash computes the deterministic hash of a trust event (excluding hash and signature fields).
func (e *TrustEvent) ComputeHash() (string, error) {
	hashable := struct {
		ID          string          `json:"id"`
		Lamport     uint64          `json:"lamport"`
		EventType   EventType       `json:"event_type"`
		SubjectID   string          `json:"subject_id"`
		SubjectType string          `json:"subject_type"`
		Payload     json.RawMessage `json:"payload"`
		PrevHash    string          `json:"prev_hash"`
		AuthorKID   string          `json:"author_kid"`
		CreatedAt   time.Time       `json:"created_at"`
	}{
		ID:          e.ID,
		Lamport:     e.Lamport,
		EventType:   e.EventType,
		SubjectID:   e.SubjectID,
		SubjectType: e.SubjectType,
		Payload:     e.Payload,
		PrevHash:    e.PrevHash,
		AuthorKID:   e.AuthorKID,
		CreatedAt:   e.CreatedAt,
	}
	data, err := canonicalize.JCS(hashable)
	if err != nil {
		return "", fmt.Errorf("canonicalize trust event: %w", err)
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// ── Trust State ─────────────────────────────────────────────

// KeyEntry is a registered key in the trust state.
type KeyEntry struct {
	KID              string  `json:"kid"`
	Algorithm        string  `json:"algorithm"`
	PublicKeyHash    string  `json:"public_key_hash"`
	OwnerDID         string  `json:"owner_did"`
	RegisteredAt     uint64  `json:"registered_at_lamport"`
	RevokedAtLamport *uint64 `json:"revoked_at_lamport,omitempty"`
}

// IsActive returns true if the key is not revoked at the given lamport height.
func (k KeyEntry) IsActive(atLamport uint64) bool {
	if k.RevokedAtLamport != nil && *k.RevokedAtLamport <= atLamport {
		return false
	}
	return true
}

// DIDEntry is a registered DID in the trust state.
type DIDEntry struct {
	DID                 string   `json:"did"`
	RegisteredAtLamport uint64   `json:"registered_at_lamport"`
	DeactivatedAt       *uint64  `json:"deactivated_at_lamport,omitempty"`
	Keys                []string `json:"keys"` // KIDs associated with this DID
}

// PolicyEntry is an activated policy in the trust state.
type PolicyEntry struct {
	PolicyID           string  `json:"policy_id"`
	Version            string  `json:"version"`
	Hash               string  `json:"hash"`
	ActivatedAtLamport uint64  `json:"activated_at_lamport"`
	RevokedAtLamport   *uint64 `json:"revoked_at_lamport,omitempty"`
}

// RoleEntry is a granted role.
type RoleEntry struct {
	SubjectID        string  `json:"subject_id"`
	Role             string  `json:"role"`
	GrantedAtLamport uint64  `json:"granted_at_lamport"`
	RevokedAtLamport *uint64 `json:"revoked_at_lamport,omitempty"`
}

// TenantEntry is a registered tenant.
type TenantEntry struct {
	TenantID            string  `json:"tenant_id"`
	RegisteredAtLamport uint64  `json:"registered_at_lamport"`
	SuspendedAtLamport  *uint64 `json:"suspended_at_lamport,omitempty"`
}

// BehavioralScoreEntry records a behavioral trust score update in the trust state.
type BehavioralScoreEntry struct {
	AgentID        string `json:"agent_id"`
	Score          int    `json:"score"`          // 0-1000
	Tier           string `json:"tier"`           // PRISTINE, TRUSTED, NEUTRAL, SUSPECT, HOSTILE
	EventType      string `json:"event_type"`     // POLICY_COMPLY, POLICY_VIOLATE, etc.
	Delta          int    `json:"delta"`           // Score change applied
	UpdatedLamport uint64 `json:"updated_lamport"`
}

// TrustState is the complete trust state at a given lamport height.
// It is derived deterministically from folding all events up to that height.
type TrustState struct {
	Lamport          uint64                          `json:"lamport"`
	Keys             map[string]KeyEntry             `json:"keys"`
	DIDs             map[string]DIDEntry             `json:"dids"`
	Policies         map[string]PolicyEntry          `json:"policies"`
	Roles            map[string][]RoleEntry          `json:"roles"` // subjectID -> roles
	Tenants          map[string]TenantEntry          `json:"tenants"`
	BehavioralScores map[string]BehavioralScoreEntry `json:"behavioral_scores,omitempty"` // agentID -> latest score
	StrictMode       bool                            `json:"-"` // Runtime-only: reject unknown event types
}

// NewTrustState creates an empty trust state (forward-compatible: unknown events silently skipped).
func NewTrustState() *TrustState {
	return &TrustState{
		Keys:             make(map[string]KeyEntry),
		DIDs:             make(map[string]DIDEntry),
		Policies:         make(map[string]PolicyEntry),
		Roles:            make(map[string][]RoleEntry),
		Tenants:          make(map[string]TenantEntry),
		BehavioralScores: make(map[string]BehavioralScoreEntry),
	}
}

// NewStrictTrustState creates a trust state that rejects unknown event types.
// Use for governance-critical domains where forward-compatibility is not desired.
func NewStrictTrustState() *TrustState {
	s := NewTrustState()
	s.StrictMode = true
	return s
}

// TrustSnapshot is a serializable, hashable snapshot of trust state at a lamport height.
type TrustSnapshot struct {
	Lamport      uint64     `json:"lamport"`
	SnapshotHash string     `json:"snapshot_hash"`
	State        TrustState `json:"state"`
	CreatedAt    time.Time  `json:"created_at"`
}
