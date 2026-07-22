// quantum_posture: GeneratedSpec approval assertions and grants use classical
// Ed25519 signatures only. This contract makes no hybrid or post-quantum claim.
package contracts

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	GeneratedSpecApprovalChallengeDomainV1   = "HELM/GeneratedSpecApprovalChallenge/v1"
	GeneratedSpecApprovalChallengeSchemaV1   = "generated-spec-approval-challenge.v1"
	GeneratedSpecApprovalChallengeContractV1 = "2026-07-22"

	GeneratedSpecApprovalAssertionDomainV1   = "HELM/GeneratedSpecApprovalAssertion/v1"
	GeneratedSpecApprovalAssertionSchemaV1   = "generated-spec-approval-assertion.v1"
	GeneratedSpecApprovalAssertionContractV1 = "2026-07-22"
	GeneratedSpecApprovalAssertionEd25519    = "ed25519"

	GeneratedSpecApprovalGrantDomainV1   = "HELM/GeneratedSpecApprovalGrant/v1"
	GeneratedSpecApprovalGrantSchemaV1   = "generated-spec-approval-grant.v1"
	GeneratedSpecApprovalGrantContractV1 = "2026-07-22"

	GeneratedSpecApprovalConsumptionDomainV1   = "HELM/GeneratedSpecApprovalConsumption/v1"
	GeneratedSpecApprovalConsumptionSchemaV1   = "generated-spec-approval-consumption.v1"
	GeneratedSpecApprovalConsumptionContractV1 = "2026-07-22"

	GeneratedSpecApprovalAudienceV1 = "generated-spec.approval"
	GeneratedSpecApprovalActionV1   = "approve_generated_spec"
)

var (
	ErrGeneratedSpecApprovalChallengeInvalid   = errors.New("generated spec approval challenge invalid")
	ErrGeneratedSpecApprovalChallengeInactive  = errors.New("generated spec approval challenge inactive")
	ErrGeneratedSpecApprovalChallengeIntegrity = errors.New("generated spec approval challenge integrity failure")
	ErrGeneratedSpecApprovalAssertionInvalid   = errors.New("generated spec approval assertion invalid")
	ErrGeneratedSpecApprovalGrantInvalid       = errors.New("generated spec approval grant invalid")
	ErrGeneratedSpecApprovalGrantInactive      = errors.New("generated spec approval grant inactive")
	ErrGeneratedSpecApprovalGrantIntegrity     = errors.New("generated spec approval grant integrity failure")
)

// GeneratedSpecApprovalChallenge is the exact server-issued proposal a human
// approver signs. Its hashes bind the immutable GeneratedSpec source, the plan
// proposed for later execution, and the policy envelope that governed review.
//
// A client-submitted copy is never evidence of issuance, elapsed hold time, or
// authority. The owning ceremony must load the durable record before accepting
// an assertion or issuing a grant.
type GeneratedSpecApprovalChallenge struct {
	Domain          string `json:"domain"`
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`

	ChallengeID string `json:"challenge_id"`
	ApprovalID  string `json:"approval_id"`
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	Audience    string `json:"audience"`

	GeneratedSpecID       string `json:"generated_spec_id"`
	GeneratedSpecHash     string `json:"generated_spec_hash"`
	ExecutionPlanHash     string `json:"execution_plan_hash"`
	PlanTransactionHash   string `json:"plan_transaction_hash"`
	WriteSetHash          string `json:"write_set_hash"`
	VerificationScopeHash string `json:"verification_scope_hash"`
	PolicyEnvelopeHash    string `json:"policy_envelope_hash"`
	PolicyVersion         string `json:"policy_version"`
	PolicyEpoch           string `json:"policy_epoch"`
	Action                string `json:"action"`

	// RequestingPrincipalID is independently sourced by the owning control
	// service. A verified signer with this identity is rejected, so the
	// requester cannot approve their own GeneratedSpec under this v1 contract.
	RequestingPrincipalID string `json:"requesting_principal_id"`

	AuthoritySource       string `json:"authority_source"`
	AuthorityVersion      string `json:"authority_version"`
	AuthoritySnapshotHash string `json:"authority_snapshot_hash"`
	RequiredRole          string `json:"required_role"`
	Quorum                int    `json:"quorum"`

	ServerIdentity string    `json:"server_identity"`
	HoldStartedAt  time.Time `json:"hold_started_at"`
	EligibleAt     time.Time `json:"eligible_at"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Nonce          string    `json:"nonce"`

	ChallengeHash string `json:"challenge_hash,omitempty"`
}

func (c GeneratedSpecApprovalChallenge) Validate() error {
	if c.Domain != GeneratedSpecApprovalChallengeDomainV1 {
		return generatedSpecApprovalChallengeInvalid("unsupported domain")
	}
	if c.SchemaVersion != GeneratedSpecApprovalChallengeSchemaV1 {
		return generatedSpecApprovalChallengeInvalid("unsupported schema_version")
	}
	if c.ContractVersion != GeneratedSpecApprovalChallengeContractV1 {
		return generatedSpecApprovalChallengeInvalid("unsupported contract_version")
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{field: "challenge_id", value: c.ChallengeID},
		{field: "approval_id", value: c.ApprovalID},
		{field: "tenant_id", value: c.TenantID},
		{field: "workspace_id", value: c.WorkspaceID},
		{field: "generated_spec_id", value: c.GeneratedSpecID},
		{field: "policy_version", value: c.PolicyVersion},
		{field: "policy_epoch", value: c.PolicyEpoch},
		{field: "requesting_principal_id", value: c.RequestingPrincipalID},
		{field: "authority_source", value: c.AuthoritySource},
		{field: "authority_version", value: c.AuthorityVersion},
		{field: "required_role", value: c.RequiredRole},
		{field: "server_identity", value: c.ServerIdentity},
	} {
		if !isApprovalGrantToken(item.value) {
			return generatedSpecApprovalChallengeInvalid(item.field + " is required and must not contain whitespace")
		}
	}
	if c.Audience != GeneratedSpecApprovalAudienceV1 {
		return generatedSpecApprovalChallengeInvalid("unsupported audience")
	}
	if c.Action != GeneratedSpecApprovalActionV1 {
		return generatedSpecApprovalChallengeInvalid("unsupported action")
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{field: "generated_spec_hash", value: c.GeneratedSpecHash},
		{field: "execution_plan_hash", value: c.ExecutionPlanHash},
		{field: "plan_transaction_hash", value: c.PlanTransactionHash},
		{field: "write_set_hash", value: c.WriteSetHash},
		{field: "verification_scope_hash", value: c.VerificationScopeHash},
		{field: "policy_envelope_hash", value: c.PolicyEnvelopeHash},
		{field: "authority_snapshot_hash", value: c.AuthoritySnapshotHash},
	} {
		if !isApprovalGrantSHA256(item.value) {
			return generatedSpecApprovalChallengeInvalid(item.field + " must be a lowercase sha256 reference")
		}
	}
	if c.Quorum <= 0 {
		return generatedSpecApprovalChallengeInvalid("quorum must be positive")
	}
	if c.HoldStartedAt.IsZero() || c.EligibleAt.IsZero() || c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() {
		return generatedSpecApprovalChallengeInvalid("hold_started_at, eligible_at, issued_at, and expires_at are required")
	}
	if !isApprovalGrantUTC(c.HoldStartedAt) || !isApprovalGrantUTC(c.EligibleAt) || !isApprovalGrantUTC(c.IssuedAt) || !isApprovalGrantUTC(c.ExpiresAt) {
		return generatedSpecApprovalChallengeInvalid("timestamps must use UTC")
	}
	if !c.EligibleAt.After(c.HoldStartedAt) {
		return generatedSpecApprovalChallengeInvalid("eligible_at must be after hold_started_at")
	}
	if c.IssuedAt.Before(c.EligibleAt) {
		return generatedSpecApprovalChallengeInvalid("issued_at must not be before eligible_at")
	}
	if !c.ExpiresAt.After(c.IssuedAt) {
		return generatedSpecApprovalChallengeInvalid("expires_at must be after issued_at")
	}
	if !isApprovalGrantNonce(c.Nonce) {
		return generatedSpecApprovalChallengeInvalid("nonce must be 32 lowercase hexadecimal bytes")
	}
	if c.ChallengeHash != "" && !isApprovalGrantSHA256(c.ChallengeHash) {
		return generatedSpecApprovalChallengeInvalid("challenge_hash must be a lowercase sha256 reference")
	}
	return nil
}

func (c GeneratedSpecApprovalChallenge) Seal() (GeneratedSpecApprovalChallenge, error) {
	if err := c.Validate(); err != nil {
		return GeneratedSpecApprovalChallenge{}, err
	}
	c.ChallengeHash = ""
	hash, err := hashJCS(c)
	if err != nil {
		return GeneratedSpecApprovalChallenge{}, fmt.Errorf("%w: seal: %v", ErrGeneratedSpecApprovalChallengeInvalid, err)
	}
	c.ChallengeHash = hash
	return c, nil
}

func (c GeneratedSpecApprovalChallenge) ValidateAt(now time.Time) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.ChallengeHash == "" {
		return fmt.Errorf("%w: challenge_hash is required", ErrGeneratedSpecApprovalChallengeIntegrity)
	}
	sealed, err := c.Seal()
	if err != nil {
		return err
	}
	if sealed.ChallengeHash != c.ChallengeHash {
		return fmt.Errorf("%w: challenge_hash mismatch", ErrGeneratedSpecApprovalChallengeIntegrity)
	}
	if now.Before(c.EligibleAt) || now.Before(c.IssuedAt) {
		return fmt.Errorf("%w: challenge is not active", ErrGeneratedSpecApprovalChallengeInactive)
	}
	if !now.Before(c.ExpiresAt) {
		return fmt.Errorf("%w: challenge is expired", ErrGeneratedSpecApprovalChallengeInactive)
	}
	return nil
}

// GeneratedSpecApprovalAssertion is a human signature over one exact
// GeneratedSpecApprovalChallenge. Principal, tenant, device, role, and action
// authority come exclusively from the trusted authority snapshot, never from
// this submitted assertion.
type GeneratedSpecApprovalAssertion struct {
	Domain          string `json:"domain"`
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`
	ChallengeID     string `json:"challenge_id"`
	ChallengeHash   string `json:"challenge_hash"`
	KeyID           string `json:"key_id"`
	Algorithm       string `json:"algorithm"`
	Signature       string `json:"signature"`
}

func (a GeneratedSpecApprovalAssertion) Validate() error {
	if err := a.validateSigningEnvelope(); err != nil {
		return err
	}
	_, err := a.SignatureBytes()
	return err
}

func (a GeneratedSpecApprovalAssertion) validateSigningEnvelope() error {
	if a.Domain != GeneratedSpecApprovalAssertionDomainV1 {
		return generatedSpecApprovalAssertionInvalid("unsupported domain")
	}
	if a.SchemaVersion != GeneratedSpecApprovalAssertionSchemaV1 {
		return generatedSpecApprovalAssertionInvalid("unsupported schema_version")
	}
	if a.ContractVersion != GeneratedSpecApprovalAssertionContractV1 {
		return generatedSpecApprovalAssertionInvalid("unsupported contract_version")
	}
	if !isApprovalGrantToken(a.ChallengeID) || !isApprovalGrantSHA256(a.ChallengeHash) || !isApprovalGrantToken(a.KeyID) {
		return generatedSpecApprovalAssertionInvalid("challenge and key bindings are required")
	}
	if a.Algorithm != GeneratedSpecApprovalAssertionEd25519 {
		return generatedSpecApprovalAssertionInvalid("algorithm must be ed25519")
	}
	return nil
}

func (a GeneratedSpecApprovalAssertion) SigningDigest() ([]byte, error) {
	if err := a.validateSigningEnvelope(); err != nil {
		return nil, err
	}
	hash, err := hashJCS(struct {
		Domain          string `json:"domain"`
		SchemaVersion   string `json:"schema_version"`
		ContractVersion string `json:"contract_version"`
		ChallengeID     string `json:"challenge_id"`
		ChallengeHash   string `json:"challenge_hash"`
		KeyID           string `json:"key_id"`
		Algorithm       string `json:"algorithm"`
	}{
		Domain: a.Domain, SchemaVersion: a.SchemaVersion, ContractVersion: a.ContractVersion,
		ChallengeID: a.ChallengeID, ChallengeHash: a.ChallengeHash, KeyID: a.KeyID, Algorithm: a.Algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: signing digest: %v", ErrGeneratedSpecApprovalAssertionInvalid, err)
	}
	return hex.DecodeString(strings.TrimPrefix(hash, "sha256:"))
}

func (a GeneratedSpecApprovalAssertion) SignatureBytes() ([]byte, error) {
	const prefix = "ed25519:"
	if !strings.HasPrefix(a.Signature, prefix) {
		return nil, generatedSpecApprovalAssertionInvalid("signature must use the ed25519 prefix")
	}
	raw := strings.TrimPrefix(a.Signature, prefix)
	if len(raw) != ed25519.SignatureSize*2 || strings.ToLower(raw) != raw {
		return nil, generatedSpecApprovalAssertionInvalid("signature must be 64 lowercase hexadecimal bytes")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, generatedSpecApprovalAssertionInvalid("signature must be 64 lowercase hexadecimal bytes")
	}
	return decoded, nil
}

// GeneratedSpecApprovalGrant carries a Kernel-signed, short-lived approval of
// one immutable GeneratedSpec. It is deliberately not execution authority:
// the Control Plane must verify the signature and atomically consume this
// grant while transitioning reviewed -> approved; execution still requires its
// own Kernel boundary decision and receipt chain.
type GeneratedSpecApprovalGrant struct {
	Domain          string `json:"domain"`
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`

	GrantID     string `json:"grant_id"`
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	Audience    string `json:"audience"`

	GeneratedSpecID       string `json:"generated_spec_id"`
	GeneratedSpecHash     string `json:"generated_spec_hash"`
	ExecutionPlanHash     string `json:"execution_plan_hash"`
	PlanTransactionHash   string `json:"plan_transaction_hash"`
	WriteSetHash          string `json:"write_set_hash"`
	VerificationScopeHash string `json:"verification_scope_hash"`
	PolicyEnvelopeHash    string `json:"policy_envelope_hash"`
	PolicyVersion         string `json:"policy_version"`
	PolicyEpoch           string `json:"policy_epoch"`
	Action                string `json:"action"`

	RequestingPrincipalID string   `json:"requesting_principal_id"`
	ApproverPrincipalIDs  []string `json:"approver_principal_ids"`

	ApprovalID            string `json:"approval_id"`
	ChallengeHash         string `json:"challenge_hash"`
	CeremonyHash          string `json:"ceremony_hash"`
	SignerSetHash         string `json:"signer_set_hash"`
	AuthoritySource       string `json:"authority_source"`
	AuthorityVersion      string `json:"authority_version"`
	AuthoritySnapshotHash string `json:"authority_snapshot_hash"`

	ServerIdentity    string    `json:"server_identity"`
	KernelTrustRootID string    `json:"kernel_trust_root_id"`
	SigningKeyRef     string    `json:"signing_key_ref"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Nonce             string    `json:"nonce"`

	GrantHash string `json:"grant_hash,omitempty"`
}

func (g GeneratedSpecApprovalGrant) Validate() error {
	if g.Domain != GeneratedSpecApprovalGrantDomainV1 {
		return generatedSpecApprovalGrantInvalid("unsupported domain")
	}
	if g.SchemaVersion != GeneratedSpecApprovalGrantSchemaV1 {
		return generatedSpecApprovalGrantInvalid("unsupported schema_version")
	}
	if g.ContractVersion != GeneratedSpecApprovalGrantContractV1 {
		return generatedSpecApprovalGrantInvalid("unsupported contract_version")
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{field: "grant_id", value: g.GrantID},
		{field: "tenant_id", value: g.TenantID},
		{field: "workspace_id", value: g.WorkspaceID},
		{field: "generated_spec_id", value: g.GeneratedSpecID},
		{field: "policy_version", value: g.PolicyVersion},
		{field: "policy_epoch", value: g.PolicyEpoch},
		{field: "requesting_principal_id", value: g.RequestingPrincipalID},
		{field: "approval_id", value: g.ApprovalID},
		{field: "authority_source", value: g.AuthoritySource},
		{field: "authority_version", value: g.AuthorityVersion},
		{field: "server_identity", value: g.ServerIdentity},
		{field: "kernel_trust_root_id", value: g.KernelTrustRootID},
		{field: "signing_key_ref", value: g.SigningKeyRef},
	} {
		if !isApprovalGrantToken(item.value) {
			return generatedSpecApprovalGrantInvalid(item.field + " is required and must not contain whitespace")
		}
	}
	if g.Audience != GeneratedSpecApprovalAudienceV1 {
		return generatedSpecApprovalGrantInvalid("unsupported audience")
	}
	if g.Action != GeneratedSpecApprovalActionV1 {
		return generatedSpecApprovalGrantInvalid("unsupported action")
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{field: "generated_spec_hash", value: g.GeneratedSpecHash},
		{field: "execution_plan_hash", value: g.ExecutionPlanHash},
		{field: "plan_transaction_hash", value: g.PlanTransactionHash},
		{field: "write_set_hash", value: g.WriteSetHash},
		{field: "verification_scope_hash", value: g.VerificationScopeHash},
		{field: "policy_envelope_hash", value: g.PolicyEnvelopeHash},
		{field: "challenge_hash", value: g.ChallengeHash},
		{field: "ceremony_hash", value: g.CeremonyHash},
		{field: "signer_set_hash", value: g.SignerSetHash},
		{field: "authority_snapshot_hash", value: g.AuthoritySnapshotHash},
	} {
		if !isApprovalGrantSHA256(item.value) {
			return generatedSpecApprovalGrantInvalid(item.field + " must be a lowercase sha256 reference")
		}
	}
	if err := validateGeneratedSpecApprovers(g.RequestingPrincipalID, g.ApproverPrincipalIDs); err != nil {
		return generatedSpecApprovalGrantInvalid(err.Error())
	}
	if g.IssuedAt.IsZero() || g.ExpiresAt.IsZero() || !isApprovalGrantUTC(g.IssuedAt) || !isApprovalGrantUTC(g.ExpiresAt) || !g.ExpiresAt.After(g.IssuedAt) {
		return generatedSpecApprovalGrantInvalid("issued_at and expires_at must be a valid UTC window")
	}
	if !isApprovalGrantNonce(g.Nonce) {
		return generatedSpecApprovalGrantInvalid("nonce must be 32 lowercase hexadecimal bytes")
	}
	if g.GrantHash != "" && !isApprovalGrantSHA256(g.GrantHash) {
		return generatedSpecApprovalGrantInvalid("grant_hash must be a lowercase sha256 reference")
	}
	return nil
}

func (g GeneratedSpecApprovalGrant) Seal() (GeneratedSpecApprovalGrant, error) {
	if err := g.Validate(); err != nil {
		return GeneratedSpecApprovalGrant{}, err
	}
	g.GrantHash = ""
	hash, err := hashJCS(g)
	if err != nil {
		return GeneratedSpecApprovalGrant{}, fmt.Errorf("%w: seal: %v", ErrGeneratedSpecApprovalGrantInvalid, err)
	}
	g.GrantHash = hash
	return g, nil
}

func (g GeneratedSpecApprovalGrant) ValidateAt(now time.Time) error {
	if err := g.Validate(); err != nil {
		return err
	}
	if g.GrantHash == "" {
		return fmt.Errorf("%w: grant_hash is required", ErrGeneratedSpecApprovalGrantIntegrity)
	}
	sealed, err := g.Seal()
	if err != nil {
		return err
	}
	if sealed.GrantHash != g.GrantHash {
		return fmt.Errorf("%w: grant_hash mismatch", ErrGeneratedSpecApprovalGrantIntegrity)
	}
	if now.Before(g.IssuedAt) || !now.Before(g.ExpiresAt) {
		return fmt.Errorf("%w: grant is not active", ErrGeneratedSpecApprovalGrantInactive)
	}
	return nil
}

// GeneratedSpecApprovalConsumption is the signed record produced when the
// control-plane workload consumes one approval grant. The durable store must
// create it in the same transaction as its single-use grant state transition.
type GeneratedSpecApprovalConsumption struct {
	Domain          string `json:"domain"`
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`

	ApprovalID string `json:"approval_id"`
	GrantID    string `json:"grant_id"`
	GrantHash  string `json:"grant_hash"`

	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	Audience    string `json:"audience"`
	ConsumedBy  string `json:"consumed_by"`

	GeneratedSpecID       string   `json:"generated_spec_id"`
	GeneratedSpecHash     string   `json:"generated_spec_hash"`
	ExecutionPlanHash     string   `json:"execution_plan_hash"`
	PlanTransactionHash   string   `json:"plan_transaction_hash"`
	WriteSetHash          string   `json:"write_set_hash"`
	VerificationScopeHash string   `json:"verification_scope_hash"`
	PolicyEnvelopeHash    string   `json:"policy_envelope_hash"`
	PolicyVersion         string   `json:"policy_version"`
	PolicyEpoch           string   `json:"policy_epoch"`
	Action                string   `json:"action"`
	RequestingPrincipalID string   `json:"requesting_principal_id"`
	ApproverPrincipalIDs  []string `json:"approver_principal_ids"`

	ChallengeHash         string `json:"challenge_hash"`
	CeremonyHash          string `json:"ceremony_hash"`
	SignerSetHash         string `json:"signer_set_hash"`
	AuthoritySource       string `json:"authority_source"`
	AuthorityVersion      string `json:"authority_version"`
	AuthoritySnapshotHash string `json:"authority_snapshot_hash"`
	ServerIdentity        string `json:"server_identity"`
	KernelTrustRootID     string `json:"kernel_trust_root_id"`
	SigningKeyRef         string `json:"signing_key_ref"`

	GrantIssuedAt  time.Time `json:"grant_issued_at"`
	GrantExpiresAt time.Time `json:"grant_expires_at"`
	ConsumedAt     time.Time `json:"consumed_at"`

	ConsumptionHash string `json:"consumption_hash,omitempty"`
}

func (c GeneratedSpecApprovalConsumption) Validate() error {
	if c.Domain != GeneratedSpecApprovalConsumptionDomainV1 || c.SchemaVersion != GeneratedSpecApprovalConsumptionSchemaV1 || c.ContractVersion != GeneratedSpecApprovalConsumptionContractV1 {
		return generatedSpecApprovalConsumptionInvalid("unsupported contract")
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{field: "approval_id", value: c.ApprovalID}, {field: "grant_id", value: c.GrantID},
		{field: "tenant_id", value: c.TenantID}, {field: "workspace_id", value: c.WorkspaceID},
		{field: "consumed_by", value: c.ConsumedBy}, {field: "generated_spec_id", value: c.GeneratedSpecID},
		{field: "policy_version", value: c.PolicyVersion}, {field: "policy_epoch", value: c.PolicyEpoch},
		{field: "requesting_principal_id", value: c.RequestingPrincipalID}, {field: "authority_source", value: c.AuthoritySource},
		{field: "authority_version", value: c.AuthorityVersion}, {field: "server_identity", value: c.ServerIdentity},
		{field: "kernel_trust_root_id", value: c.KernelTrustRootID}, {field: "signing_key_ref", value: c.SigningKeyRef},
	} {
		if !isApprovalGrantToken(item.value) {
			return generatedSpecApprovalConsumptionInvalid(item.field + " is required and must not contain whitespace")
		}
	}
	if c.Audience != GeneratedSpecApprovalAudienceV1 || c.Action != GeneratedSpecApprovalActionV1 {
		return generatedSpecApprovalConsumptionInvalid("unsupported audience or action")
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{field: "grant_hash", value: c.GrantHash}, {field: "generated_spec_hash", value: c.GeneratedSpecHash},
		{field: "execution_plan_hash", value: c.ExecutionPlanHash}, {field: "plan_transaction_hash", value: c.PlanTransactionHash},
		{field: "write_set_hash", value: c.WriteSetHash}, {field: "verification_scope_hash", value: c.VerificationScopeHash},
		{field: "policy_envelope_hash", value: c.PolicyEnvelopeHash}, {field: "challenge_hash", value: c.ChallengeHash},
		{field: "ceremony_hash", value: c.CeremonyHash}, {field: "signer_set_hash", value: c.SignerSetHash},
		{field: "authority_snapshot_hash", value: c.AuthoritySnapshotHash},
	} {
		if !isApprovalGrantSHA256(item.value) {
			return generatedSpecApprovalConsumptionInvalid(item.field + " must be a lowercase sha256 reference")
		}
	}
	if err := validateGeneratedSpecApprovers(c.RequestingPrincipalID, c.ApproverPrincipalIDs); err != nil {
		return generatedSpecApprovalConsumptionInvalid(err.Error())
	}
	if c.GrantIssuedAt.IsZero() || c.GrantExpiresAt.IsZero() || c.ConsumedAt.IsZero() || !isApprovalGrantUTC(c.GrantIssuedAt) || !isApprovalGrantUTC(c.GrantExpiresAt) || !isApprovalGrantUTC(c.ConsumedAt) || c.ConsumedAt.Before(c.GrantIssuedAt) || !c.ConsumedAt.Before(c.GrantExpiresAt) {
		return generatedSpecApprovalConsumptionInvalid("timestamps are outside the grant lifetime")
	}
	if c.ConsumptionHash != "" && !isApprovalGrantSHA256(c.ConsumptionHash) {
		return generatedSpecApprovalConsumptionInvalid("consumption_hash must be a lowercase sha256 reference")
	}
	return nil
}

func (c GeneratedSpecApprovalConsumption) Seal() (GeneratedSpecApprovalConsumption, error) {
	if err := c.Validate(); err != nil {
		return GeneratedSpecApprovalConsumption{}, err
	}
	c.ConsumptionHash = ""
	hash, err := hashJCS(c)
	if err != nil {
		return GeneratedSpecApprovalConsumption{}, fmt.Errorf("%w: seal: %v", ErrGeneratedSpecApprovalGrantIntegrity, err)
	}
	c.ConsumptionHash = hash
	return c, nil
}

func (c GeneratedSpecApprovalConsumption) ValidateGrant(g GeneratedSpecApprovalGrant) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.ConsumptionHash == "" {
		return generatedSpecApprovalConsumptionInvalid("consumption_hash is required")
	}
	sealed, err := c.Seal()
	if err != nil || sealed.ConsumptionHash != c.ConsumptionHash {
		return generatedSpecApprovalConsumptionInvalid("consumption integrity mismatch")
	}
	if err := g.Validate(); err != nil || g.GrantHash == "" {
		return generatedSpecApprovalConsumptionInvalid("sealed grant is required")
	}
	sealedGrant, err := g.Seal()
	if err != nil || sealedGrant.GrantHash != g.GrantHash {
		return generatedSpecApprovalConsumptionInvalid("grant integrity mismatch")
	}
	if c.ApprovalID != g.ApprovalID || c.GrantID != g.GrantID || c.GrantHash != g.GrantHash ||
		c.TenantID != g.TenantID || c.WorkspaceID != g.WorkspaceID || c.Audience != g.Audience ||
		c.GeneratedSpecID != g.GeneratedSpecID || c.GeneratedSpecHash != g.GeneratedSpecHash ||
		c.ExecutionPlanHash != g.ExecutionPlanHash || c.PlanTransactionHash != g.PlanTransactionHash ||
		c.WriteSetHash != g.WriteSetHash || c.VerificationScopeHash != g.VerificationScopeHash ||
		c.PolicyEnvelopeHash != g.PolicyEnvelopeHash ||
		c.PolicyVersion != g.PolicyVersion || c.PolicyEpoch != g.PolicyEpoch || c.Action != g.Action ||
		c.RequestingPrincipalID != g.RequestingPrincipalID || !sameStringSlice(c.ApproverPrincipalIDs, g.ApproverPrincipalIDs) ||
		c.ChallengeHash != g.ChallengeHash || c.CeremonyHash != g.CeremonyHash || c.SignerSetHash != g.SignerSetHash ||
		c.AuthoritySource != g.AuthoritySource || c.AuthorityVersion != g.AuthorityVersion ||
		c.AuthoritySnapshotHash != g.AuthoritySnapshotHash || c.ServerIdentity != g.ServerIdentity ||
		c.KernelTrustRootID != g.KernelTrustRootID || c.SigningKeyRef != g.SigningKeyRef ||
		!c.GrantIssuedAt.Equal(g.IssuedAt) || !c.GrantExpiresAt.Equal(g.ExpiresAt) {
		return generatedSpecApprovalConsumptionInvalid("consumption does not match sealed grant")
	}
	return nil
}

func validateGeneratedSpecApprovers(requester string, approvers []string) error {
	if len(approvers) == 0 {
		return errors.New("approver_principal_ids is required")
	}
	if !sort.StringsAreSorted(approvers) {
		return errors.New("approver_principal_ids must be sorted")
	}
	for index, approver := range approvers {
		if !isApprovalGrantToken(approver) {
			return errors.New("approver_principal_ids contains an invalid principal")
		}
		if approver == requester {
			return errors.New("requester cannot approve its own generated spec")
		}
		if index > 0 && approvers[index-1] == approver {
			return errors.New("approver_principal_ids must be unique")
		}
	}
	return nil
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func generatedSpecApprovalChallengeInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrGeneratedSpecApprovalChallengeInvalid, message)
}

func generatedSpecApprovalAssertionInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrGeneratedSpecApprovalAssertionInvalid, message)
}

func generatedSpecApprovalGrantInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrGeneratedSpecApprovalGrantInvalid, message)
}

func generatedSpecApprovalConsumptionInvalid(message string) error {
	return fmt.Errorf("%w: consumption: %s", ErrGeneratedSpecApprovalGrantIntegrity, message)
}
