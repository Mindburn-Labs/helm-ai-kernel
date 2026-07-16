// quantum_posture: approval assertions use classical Ed25519 signatures;
// this contract does not claim hybrid or post-quantum approval authority.
package contracts

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ApprovalChallengeDomainV1   = "HELM/ApprovalChallenge/v1"
	ApprovalChallengeSchemaV1   = "approval-challenge.v1"
	ApprovalChallengeContractV1 = "2026-07-15"

	ApprovalAssertionDomainV1   = "HELM/ApprovalAssertion/v1"
	ApprovalAssertionSchemaV1   = "approval-assertion.v1"
	ApprovalAssertionContractV1 = "2026-07-15"
	ApprovalAssertionEd25519    = "ed25519"
)

var (
	ErrApprovalChallengeInvalid   = errors.New("approval challenge invalid")
	ErrApprovalChallengeInactive  = errors.New("approval challenge inactive")
	ErrApprovalChallengeIntegrity = errors.New("approval challenge integrity failure")
	ErrApprovalAssertionInvalid   = errors.New("approval assertion invalid")
)

// ApprovalChallenge is the canonical server-issued payload an approver signs.
// Server timestamps and ChallengeHash are authoritative only when this record
// is loaded from the owning durable ceremony store; a client-submitted copy is
// not proof of elapsed hold time or policy authority.
type ApprovalChallenge struct {
	Domain          string `json:"domain"`
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`

	ChallengeID string `json:"challenge_id"`
	ApprovalID  string `json:"approval_id"`
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	Audience    string `json:"audience"`

	PackID           string `json:"pack_id"`
	PackVersion      string `json:"pack_version"`
	PackManifestHash string `json:"pack_manifest_hash"`
	Action           string `json:"action"`

	IntentHash string `json:"intent_hash"`
	EffectHash string `json:"effect_hash"`
	PlanHash   string `json:"plan_hash"`
	Decision   string `json:"decision"`

	PolicyVersion string `json:"policy_version"`
	PolicyEpoch   string `json:"policy_epoch"`
	PolicyHash    string `json:"policy_hash"`

	AuthoritySource       string `json:"authority_source"`
	AuthorityVersion      string `json:"authority_version"`
	AuthoritySnapshotHash string `json:"authority_snapshot_hash"`

	RequiredRole string `json:"required_role"`
	Quorum       int    `json:"quorum"`

	ServerIdentity string    `json:"server_identity"`
	HoldStartedAt  time.Time `json:"hold_started_at"`
	EligibleAt     time.Time `json:"eligible_at"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Nonce          string    `json:"nonce"`

	ChallengeHash string `json:"challenge_hash,omitempty"`
}

func (c ApprovalChallenge) Validate() error {
	if c.Domain != ApprovalChallengeDomainV1 {
		return approvalChallengeInvalid("unsupported domain")
	}
	if c.SchemaVersion != ApprovalChallengeSchemaV1 {
		return approvalChallengeInvalid("unsupported schema_version")
	}
	if c.ContractVersion != ApprovalChallengeContractV1 {
		return approvalChallengeInvalid("unsupported contract_version")
	}

	required := []struct {
		field string
		value string
	}{
		{field: "challenge_id", value: c.ChallengeID},
		{field: "approval_id", value: c.ApprovalID},
		{field: "tenant_id", value: c.TenantID},
		{field: "workspace_id", value: c.WorkspaceID},
		{field: "audience", value: c.Audience},
		{field: "pack_id", value: c.PackID},
		{field: "pack_version", value: c.PackVersion},
		{field: "policy_version", value: c.PolicyVersion},
		{field: "policy_epoch", value: c.PolicyEpoch},
		{field: "authority_source", value: c.AuthoritySource},
		{field: "authority_version", value: c.AuthorityVersion},
		{field: "required_role", value: c.RequiredRole},
		{field: "server_identity", value: c.ServerIdentity},
	}
	for _, item := range required {
		if !isApprovalGrantToken(item.value) {
			return approvalChallengeInvalid(item.field + " is required and must not contain whitespace")
		}
	}

	hashes := []struct {
		field string
		value string
	}{
		{field: "pack_manifest_hash", value: c.PackManifestHash},
		{field: "intent_hash", value: c.IntentHash},
		{field: "effect_hash", value: c.EffectHash},
		{field: "plan_hash", value: c.PlanHash},
		{field: "policy_hash", value: c.PolicyHash},
		{field: "authority_snapshot_hash", value: c.AuthoritySnapshotHash},
	}
	for _, item := range hashes {
		if !isApprovalGrantSHA256(item.value) {
			return approvalChallengeInvalid(item.field + " must be a lowercase sha256 reference")
		}
	}

	switch c.Action {
	case ApprovalGrantActionInstall,
		ApprovalGrantActionUpgrade,
		ApprovalGrantActionUninstall,
		ApprovalGrantActionRollback:
	default:
		return approvalChallengeInvalid("unsupported action")
	}
	if c.Decision != ApprovalGrantDecisionAllow {
		return approvalChallengeInvalid("decision must be ALLOW")
	}
	if c.Quorum <= 0 {
		return approvalChallengeInvalid("quorum must be positive")
	}
	if c.HoldStartedAt.IsZero() || c.EligibleAt.IsZero() || c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() {
		return approvalChallengeInvalid("hold_started_at, eligible_at, issued_at, and expires_at are required")
	}
	if !isApprovalGrantUTC(c.HoldStartedAt) || !isApprovalGrantUTC(c.EligibleAt) || !isApprovalGrantUTC(c.IssuedAt) || !isApprovalGrantUTC(c.ExpiresAt) {
		return approvalChallengeInvalid("hold_started_at, eligible_at, issued_at, and expires_at must use UTC")
	}
	if !c.EligibleAt.After(c.HoldStartedAt) {
		return approvalChallengeInvalid("eligible_at must be after hold_started_at")
	}
	if c.IssuedAt.Before(c.EligibleAt) {
		return approvalChallengeInvalid("issued_at must not be before eligible_at")
	}
	if !c.ExpiresAt.After(c.IssuedAt) {
		return approvalChallengeInvalid("expires_at must be after issued_at")
	}
	if !isApprovalGrantNonce(c.Nonce) {
		return approvalChallengeInvalid("nonce must be 32 lowercase hexadecimal bytes")
	}
	if c.ChallengeHash != "" && !isApprovalGrantSHA256(c.ChallengeHash) {
		return approvalChallengeInvalid("challenge_hash must be a lowercase sha256 reference")
	}
	return nil
}

// Seal creates the domain-separated JCS hash referenced by approval assertions.
// The signable challenge, including its fresh nonce, MUST be minted and released
// from the owning durable ceremony no earlier than IssuedAt, and IssuedAt cannot
// precede EligibleAt. The timestamp alone does not prove release time; callers
// MUST load issuance provenance from that durable store rather than accept a
// client-submitted challenge.
func (c ApprovalChallenge) Seal() (ApprovalChallenge, error) {
	if err := c.Validate(); err != nil {
		return ApprovalChallenge{}, err
	}
	c.ChallengeHash = ""
	hash, err := hashJCS(c)
	if err != nil {
		return ApprovalChallenge{}, fmt.Errorf("%w: seal: %v", ErrApprovalChallengeInvalid, err)
	}
	c.ChallengeHash = hash
	return c, nil
}

// ValidateAt verifies the sealed challenge and its server-measured active
// window. It does not prove the record came from durable server state.
func (c ApprovalChallenge) ValidateAt(now time.Time) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.ChallengeHash == "" {
		return fmt.Errorf("%w: challenge_hash is required", ErrApprovalChallengeIntegrity)
	}
	sealed, err := c.Seal()
	if err != nil {
		return err
	}
	if sealed.ChallengeHash != c.ChallengeHash {
		return fmt.Errorf("%w: challenge_hash mismatch", ErrApprovalChallengeIntegrity)
	}
	if now.Before(c.EligibleAt) {
		return fmt.Errorf("%w: hold has not elapsed", ErrApprovalChallengeInactive)
	}
	if now.Before(c.IssuedAt) {
		return fmt.Errorf("%w: challenge is not yet issued", ErrApprovalChallengeInactive)
	}
	if !now.Before(c.ExpiresAt) {
		return fmt.Errorf("%w: challenge is expired", ErrApprovalChallengeInactive)
	}
	return nil
}

// ApprovalAssertion carries only the credential key reference and signature.
// Principal, tenant, device, role, and action authority MUST come from a
// trusted registry; client-submitted actor or public-key claims are excluded.
type ApprovalAssertion struct {
	Domain          string `json:"domain"`
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`
	ChallengeID     string `json:"challenge_id"`
	ChallengeHash   string `json:"challenge_hash"`
	KeyID           string `json:"key_id"`
	Algorithm       string `json:"algorithm"`
	Signature       string `json:"signature"`
}

func (a ApprovalAssertion) Validate() error {
	if err := a.validateSigningEnvelope(); err != nil {
		return err
	}
	if _, err := a.SignatureBytes(); err != nil {
		return err
	}
	return nil
}

func (a ApprovalAssertion) validateSigningEnvelope() error {
	if a.Domain != ApprovalAssertionDomainV1 {
		return approvalAssertionInvalid("unsupported domain")
	}
	if a.SchemaVersion != ApprovalAssertionSchemaV1 {
		return approvalAssertionInvalid("unsupported schema_version")
	}
	if a.ContractVersion != ApprovalAssertionContractV1 {
		return approvalAssertionInvalid("unsupported contract_version")
	}
	if !isApprovalGrantToken(a.ChallengeID) {
		return approvalAssertionInvalid("challenge_id is required and must not contain whitespace")
	}
	if !isApprovalGrantSHA256(a.ChallengeHash) {
		return approvalAssertionInvalid("challenge_hash must be a lowercase sha256 reference")
	}
	if !IsApprovalSignerIdentifier(a.KeyID) {
		return approvalAssertionInvalid("key_id must use the portable ASCII signer identifier grammar")
	}
	if a.Algorithm != ApprovalAssertionEd25519 {
		return approvalAssertionInvalid("algorithm must be ed25519")
	}
	return nil
}

// IsApprovalSignerIdentifier reports whether value has the portable,
// case-sensitive ASCII grammar used for deterministic signer-set ordering.
func IsApprovalSignerIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '.', '_', '~', ':', '/', '@', '+', '-':
			continue
		default:
			return false
		}
	}
	return true
}

// SigningDigest returns the domain-separated JCS digest signed by the
// assertion key. It binds the assertion contract, challenge, key selection,
// and algorithm; Signature itself is deliberately excluded.
func (a ApprovalAssertion) SigningDigest() ([]byte, error) {
	if err := a.validateSigningEnvelope(); err != nil {
		return nil, err
	}
	payload := struct {
		Domain          string `json:"domain"`
		SchemaVersion   string `json:"schema_version"`
		ContractVersion string `json:"contract_version"`
		ChallengeID     string `json:"challenge_id"`
		ChallengeHash   string `json:"challenge_hash"`
		KeyID           string `json:"key_id"`
		Algorithm       string `json:"algorithm"`
	}{
		Domain:          a.Domain,
		SchemaVersion:   a.SchemaVersion,
		ContractVersion: a.ContractVersion,
		ChallengeID:     a.ChallengeID,
		ChallengeHash:   a.ChallengeHash,
		KeyID:           a.KeyID,
		Algorithm:       a.Algorithm,
	}
	hash, err := hashJCS(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: signing digest: %v", ErrApprovalAssertionInvalid, err)
	}
	return hex.DecodeString(strings.TrimPrefix(hash, "sha256:"))
}

func (a ApprovalAssertion) SignatureBytes() ([]byte, error) {
	const prefix = "ed25519:"
	if !strings.HasPrefix(a.Signature, prefix) {
		return nil, approvalAssertionInvalid("signature must use the ed25519 prefix")
	}
	raw := strings.TrimPrefix(a.Signature, prefix)
	if len(raw) != ed25519.SignatureSize*2 || strings.ToLower(raw) != raw {
		return nil, approvalAssertionInvalid("signature must be 64 lowercase hexadecimal bytes")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, approvalAssertionInvalid("signature must be 64 lowercase hexadecimal bytes")
	}
	return decoded, nil
}

func approvalChallengeInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrApprovalChallengeInvalid, message)
}

func approvalAssertionInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrApprovalAssertionInvalid, message)
}
