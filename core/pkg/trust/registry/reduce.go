package registry

import (
	"encoding/json"
	"fmt"
)

// Reducer folds TrustEvents into TrustState deterministically.
// Given the same sequence of events, every node produces identical TrustState bytes.
//
// Rules:
//   - Events are processed in lamport order (ascending).
//   - Duplicate lamport values within the same subject are rejected.
//   - Revocations set *_at_lamport fields; subsequent lookups at higher lamport fail-closed.
//   - Unknown event types are silently skipped (forward compatibility).

// Apply applies a single trust event to the state, returning an error if the event is invalid.
func (s *TrustState) Apply(event *TrustEvent) error {
	if event.Lamport < s.Lamport {
		return fmt.Errorf("event lamport %d is less than state lamport %d (out of order)", event.Lamport, s.Lamport)
	}
	s.Lamport = event.Lamport

	switch EventType(event.EventType) {
	case EventDIDRegister:
		return s.applyDIDRegister(event)
	case EventDIDDeactivate:
		return s.applyDIDDeactivate(event)
	case EventKeyPublish:
		return s.applyKeyPublish(event)
	case EventKeyRevoke:
		return s.applyKeyRevoke(event)
	case EventKeyRotate:
		return s.applyKeyRotate(event)
	case EventPolicyActivate:
		return s.applyPolicyActivate(event)
	case EventPolicyRevoke:
		return s.applyPolicyRevoke(event)
	case EventRoleGrant:
		return s.applyRoleGrant(event)
	case EventRoleRevoke:
		return s.applyRoleRevoke(event)
	case EventTenantRegister:
		return s.applyTenantRegister(event)
	case EventTenantSuspend:
		return s.applyTenantSuspend(event)
	case EventTrustScoreUpdate:
		return s.applyTrustScoreUpdate(event)
	default:
		if s.StrictMode {
			return fmt.Errorf("strict mode: unknown trust event type %q (event %s)", event.EventType, event.ID)
		}
		// Forward compatibility: skip unknown event types
		return nil
	}
}

// Reduce folds a sequence of events into this state. Events must be in lamport order.
func (s *TrustState) Reduce(events []*TrustEvent) error {
	for _, event := range events {
		if err := s.Apply(event); err != nil {
			return fmt.Errorf("event %s (lamport %d): %w", event.ID, event.Lamport, err)
		}
	}
	return nil
}

// ── DID Handlers ─────────────────────────────────────────────

type didRegisterPayload struct {
	DID string `json:"did"`
}

func (s *TrustState) applyDIDRegister(event *TrustEvent) error {
	var p didRegisterPayload
	if err := json.Unmarshal(event.Payload, &p); err != nil {
		return fmt.Errorf("invalid DID_REGISTER payload: %w", err)
	}
	if _, exists := s.DIDs[p.DID]; exists {
		return fmt.Errorf("DID %s already registered", p.DID)
	}
	s.DIDs[p.DID] = DIDEntry{
		DID:                 p.DID,
		RegisteredAtLamport: event.Lamport,
		Keys:                []string{},
	}
	return nil
}

func (s *TrustState) applyDIDDeactivate(event *TrustEvent) error {
	var p didRegisterPayload
	if err := json.Unmarshal(event.Payload, &p); err != nil {
		return fmt.Errorf("invalid DID_DEACTIVATE payload: %w", err)
	}
	entry, exists := s.DIDs[p.DID]
	if !exists {
		return fmt.Errorf("DID %s not found", p.DID)
	}
	lamport := event.Lamport
	entry.DeactivatedAt = &lamport
	s.DIDs[p.DID] = entry
	return nil
}

// ── Key Handlers ─────────────────────────────────────────────

type keyPublishPayload struct {
	KID           string `json:"kid"`
	Algorithm     string `json:"algorithm"`
	PublicKeyHash string `json:"public_key_hash"`
	OwnerDID      string `json:"owner_did"`
}

func (s *TrustState) applyKeyPublish(event *TrustEvent) error {
	var p keyPublishPayload
	if err := json.Unmarshal(event.Payload, &p); err != nil {
		return fmt.Errorf("invalid KEY_PUBLISH payload: %w", err)
	}
	if _, exists := s.Keys[p.KID]; exists {
		return fmt.Errorf("key %s already published", p.KID)
	}
	s.Keys[p.KID] = KeyEntry{
		KID:           p.KID,
		Algorithm:     p.Algorithm,
		PublicKeyHash: p.PublicKeyHash,
		OwnerDID:      p.OwnerDID,
		RegisteredAt:  event.Lamport,
	}
	// Associate key with DID if it exists
	if entry, ok := s.DIDs[p.OwnerDID]; ok {
		entry.Keys = append(entry.Keys, p.KID)
		s.DIDs[p.OwnerDID] = entry
	}
	return nil
}

type keyRevokePayload struct {
	KID string `json:"kid"`
}

func (s *TrustState) applyKeyRevoke(event *TrustEvent) error {
	var p keyRevokePayload
	if err := json.Unmarshal(event.Payload, &p); err != nil {
		return fmt.Errorf("invalid KEY_REVOKE payload: %w", err)
	}
	entry, exists := s.Keys[p.KID]
	if !exists {
		return fmt.Errorf("key %s not found", p.KID)
	}
	lamport := event.Lamport
	entry.RevokedAtLamport = &lamport
	s.Keys[p.KID] = entry
	return nil
}

type keyRotatePayload struct {
	OldKID string `json:"old_kid"`
	NewKID string `json:"new_kid"`
}

func (s *TrustState) applyKeyRotate(event *TrustEvent) error {
	var p keyRotatePayload
	if err := json.Unmarshal(event.Payload, &p); err != nil {
		return fmt.Errorf("invalid KEY_ROTATE payload: %w", err)
	}
	// Revoke old key
	if old, ok := s.Keys[p.OldKID]; ok {
		lamport := event.Lamport
		old.RevokedAtLamport = &lamport
		s.Keys[p.OldKID] = old
	}
	// New key must already be published (KEY_PUBLISH should precede KEY_ROTATE)
	if _, ok := s.Keys[p.NewKID]; !ok {
		return fmt.Errorf("new key %s must be published before rotation", p.NewKID)
	}
	return nil
}

// ── Policy Handlers ──────────────────────────────────────────

type policyActivatePayload struct {
	PolicyID string `json:"policy_id"`
	Version  string `json:"version"`
	Hash     string `json:"hash"`
}

func (s *TrustState) applyPolicyActivate(event *TrustEvent) error {
	var p policyActivatePayload
	if err := json.Unmarshal(event.Payload, &p); err != nil {
		return fmt.Errorf("invalid POLICY_ACTIVATE payload: %w", err)
	}
	s.Policies[p.PolicyID] = PolicyEntry{
		PolicyID:           p.PolicyID,
		Version:            p.Version,
		Hash:               p.Hash,
		ActivatedAtLamport: event.Lamport,
	}
	return nil
}

func (s *TrustState) applyPolicyRevoke(event *TrustEvent) error {
	var p struct {
		PolicyID string `json:"policy_id"`
	}
	if err := json.Unmarshal(event.Payload, &p); err != nil {
		return fmt.Errorf("invalid POLICY_REVOKE payload: %w", err)
	}
	entry, exists := s.Policies[p.PolicyID]
	if !exists {
		return fmt.Errorf("policy %s not found", p.PolicyID)
	}
	lamport := event.Lamport
	entry.RevokedAtLamport = &lamport
	s.Policies[p.PolicyID] = entry
	return nil
}

// ── Role Handlers ────────────────────────────────────────────

type rolePayload struct {
	SubjectID string `json:"subject_id"`
	Role      string `json:"role"`
}

func (s *TrustState) applyRoleGrant(event *TrustEvent) error {
	var p rolePayload
	if err := json.Unmarshal(event.Payload, &p); err != nil {
		return fmt.Errorf("invalid ROLE_GRANT payload: %w", err)
	}
	s.Roles[p.SubjectID] = append(s.Roles[p.SubjectID], RoleEntry{
		SubjectID:        p.SubjectID,
		Role:             p.Role,
		GrantedAtLamport: event.Lamport,
	})
	return nil
}

func (s *TrustState) applyRoleRevoke(event *TrustEvent) error {
	var p rolePayload
	if err := json.Unmarshal(event.Payload, &p); err != nil {
		return fmt.Errorf("invalid ROLE_REVOKE payload: %w", err)
	}
	roles := s.Roles[p.SubjectID]
	for i, r := range roles {
		if r.Role == p.Role && r.RevokedAtLamport == nil {
			lamport := event.Lamport
			roles[i].RevokedAtLamport = &lamport
		}
	}
	s.Roles[p.SubjectID] = roles
	return nil
}

// ── Tenant Handlers ──────────────────────────────────────────

type tenantPayload struct {
	TenantID string `json:"tenant_id"`
}

func (s *TrustState) applyTenantRegister(event *TrustEvent) error {
	var p tenantPayload
	if err := json.Unmarshal(event.Payload, &p); err != nil {
		return fmt.Errorf("invalid TENANT_REGISTER payload: %w", err)
	}
	if _, exists := s.Tenants[p.TenantID]; exists {
		return fmt.Errorf("tenant %s already registered", p.TenantID)
	}
	s.Tenants[p.TenantID] = TenantEntry{
		TenantID:            p.TenantID,
		RegisteredAtLamport: event.Lamport,
	}
	return nil
}

func (s *TrustState) applyTenantSuspend(event *TrustEvent) error {
	var p tenantPayload
	if err := json.Unmarshal(event.Payload, &p); err != nil {
		return fmt.Errorf("invalid TENANT_SUSPEND payload: %w", err)
	}
	entry, exists := s.Tenants[p.TenantID]
	if !exists {
		return fmt.Errorf("tenant %s not found", p.TenantID)
	}
	lamport := event.Lamport
	entry.SuspendedAtLamport = &lamport
	s.Tenants[p.TenantID] = entry
	return nil
}

// ── Behavioral Trust Score Handler ──────────────────────────

type trustScoreUpdatePayload struct {
	AgentID   string `json:"agent_id"`
	Score     int    `json:"score"`
	Tier      string `json:"tier"`
	EventType string `json:"score_event_type"`
	Delta     int    `json:"delta"`
}

func (s *TrustState) applyTrustScoreUpdate(event *TrustEvent) error {
	var p trustScoreUpdatePayload
	if err := json.Unmarshal(event.Payload, &p); err != nil {
		return fmt.Errorf("invalid TRUST_SCORE_UPDATE payload: %w", err)
	}
	if p.AgentID == "" {
		return fmt.Errorf("TRUST_SCORE_UPDATE requires agent_id")
	}
	s.BehavioralScores[p.AgentID] = BehavioralScoreEntry{
		AgentID:        p.AgentID,
		Score:          p.Score,
		Tier:           p.Tier,
		EventType:      p.EventType,
		Delta:          p.Delta,
		UpdatedLamport: event.Lamport,
	}
	return nil
}
