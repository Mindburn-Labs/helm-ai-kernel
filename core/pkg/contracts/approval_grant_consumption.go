package contracts

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

const (
	ApprovalGrantConsumptionSchemaV1   = "approval-grant-consumption.v1"
	ApprovalGrantConsumptionContractV1 = "2026-07-16"
	ApprovalGrantConsumptionSchemaV2   = "approval-grant-consumption.v2"
	ApprovalGrantConsumptionContractV2 = "2026-07-18"
)

// ApprovalGrantConsumption is the portable, Kernel-signed record that a
// specific workload consumed one ApprovalGrant. It is deliberately scoped to
// the versioned action tuple already sealed by ApprovalGrant: V1 is pack
// lifecycle only and V2 is only the policy-draft sandbox. It must not be
// promoted into a generic connector or arbitrary agent-effect permit.
//
// The ceremony store persists this record in the same transaction that moves
// the grant to CONSUMED. A dispatcher may recover the exact record after a
// response loss, but still needs its own durable grant_hash CAS before invoking
// its exact permitted consumer.
type ApprovalGrantConsumption struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`

	ApprovalID string `json:"approval_id"`
	GrantID    string `json:"grant_id"`
	GrantHash  string `json:"grant_hash"`

	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	Audience    string `json:"audience"`
	ConsumedBy  string `json:"consumed_by"`

	PackID           string `json:"pack_id"`
	PackVersion      string `json:"pack_version"`
	PackManifestHash string `json:"pack_manifest_hash"`
	Action           string `json:"action"`

	IntentHash string `json:"intent_hash"`
	EffectHash string `json:"effect_hash"`
	PlanHash   string `json:"plan_hash"`

	PolicyVersion string `json:"policy_version"`
	PolicyEpoch   string `json:"policy_epoch"`
	PolicyHash    string `json:"policy_hash"`

	ServerIdentity    string `json:"server_identity"`
	KernelTrustRootID string `json:"kernel_trust_root_id"`
	SigningKeyRef     string `json:"signing_key_ref"`

	GrantIssuedAt  time.Time `json:"grant_issued_at"`
	GrantExpiresAt time.Time `json:"grant_expires_at"`
	ConsumedAt     time.Time `json:"consumed_at"`

	ConsumptionHash string `json:"consumption_hash,omitempty"`
}

func (c ApprovalGrantConsumption) Validate() error {
	switch c.SchemaVersion {
	case ApprovalGrantConsumptionSchemaV1:
		if c.ContractVersion != ApprovalGrantConsumptionContractV1 {
			return approvalGrantConsumptionInvalid("unsupported contract_version")
		}
	case ApprovalGrantConsumptionSchemaV2:
		if c.ContractVersion != ApprovalGrantConsumptionContractV2 {
			return approvalGrantConsumptionInvalid("unsupported contract_version")
		}
	default:
		return approvalGrantConsumptionInvalid("unsupported schema_version")
	}
	for field, value := range map[string]string{
		"approval_id": c.ApprovalID, "grant_id": c.GrantID,
		"tenant_id": c.TenantID, "workspace_id": c.WorkspaceID,
		"audience": c.Audience, "consumed_by": c.ConsumedBy,
		"pack_id": c.PackID, "pack_version": c.PackVersion,
		"policy_version": c.PolicyVersion, "policy_epoch": c.PolicyEpoch,
		"server_identity": c.ServerIdentity, "kernel_trust_root_id": c.KernelTrustRootID,
		"signing_key_ref": c.SigningKeyRef,
	} {
		if !isApprovalGrantConsumptionToken(value) {
			return approvalGrantConsumptionInvalid(field + " is required and must not contain whitespace")
		}
	}
	for field, value := range map[string]string{
		"grant_hash": c.GrantHash, "pack_manifest_hash": c.PackManifestHash,
		"intent_hash": c.IntentHash, "effect_hash": c.EffectHash,
		"plan_hash": c.PlanHash, "policy_hash": c.PolicyHash,
	} {
		if !isApprovalGrantSHA256(value) {
			return approvalGrantConsumptionInvalid(field + " must be a lowercase sha256 reference")
		}
	}
	grantSchemaVersion := ApprovalGrantSchemaV1
	if c.SchemaVersion == ApprovalGrantConsumptionSchemaV2 {
		grantSchemaVersion = ApprovalGrantSchemaV2
	}
	if err := validateApprovalGrantActionScope(grantSchemaVersion, c.Audience, c.PackID, c.Action); err != nil {
		return approvalGrantConsumptionInvalid(err.Error())
	}
	if c.GrantIssuedAt.IsZero() || c.GrantExpiresAt.IsZero() || c.ConsumedAt.IsZero() {
		return approvalGrantConsumptionInvalid("grant and consumption timestamps are required")
	}
	if !isApprovalGrantUTC(c.GrantIssuedAt) || !isApprovalGrantUTC(c.GrantExpiresAt) || !isApprovalGrantUTC(c.ConsumedAt) {
		return approvalGrantConsumptionInvalid("timestamps must use UTC")
	}
	if c.ConsumedAt.Before(c.GrantIssuedAt) || !c.ConsumedAt.Before(c.GrantExpiresAt) {
		return approvalGrantConsumptionInvalid("consumed_at is outside the grant lifetime")
	}
	if c.ConsumptionHash != "" && !isApprovalGrantSHA256(c.ConsumptionHash) {
		return approvalGrantConsumptionInvalid("consumption_hash must be a lowercase sha256 reference")
	}
	return nil
}

func (c ApprovalGrantConsumption) Seal() (ApprovalGrantConsumption, error) {
	if err := c.Validate(); err != nil {
		return ApprovalGrantConsumption{}, err
	}
	c.ConsumptionHash = ""
	hash, err := hashJCS(c)
	if err != nil {
		return ApprovalGrantConsumption{}, fmt.Errorf("%w: seal: %v", ErrApprovalGrantIntegrity, err)
	}
	c.ConsumptionHash = hash
	return c, nil
}

// ValidateGrant proves that the consumption record is an exact projection of
// one sealed ApprovalGrant. Signature trust is established separately.
func (c ApprovalGrantConsumption) ValidateGrant(grant ApprovalGrant) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.ConsumptionHash == "" {
		return approvalGrantConsumptionInvalid("consumption_hash is required")
	}
	sealed, err := c.Seal()
	if err != nil || sealed.ConsumptionHash != c.ConsumptionHash {
		return approvalGrantConsumptionInvalid("consumption integrity mismatch")
	}
	if err := grant.Validate(); err != nil {
		return approvalGrantConsumptionInvalid("grant: " + err.Error())
	}
	if grant.GrantHash == "" {
		return approvalGrantConsumptionInvalid("grant_hash is required")
	}
	sealedGrant, err := grant.Seal()
	if err != nil || sealedGrant.GrantHash != grant.GrantHash {
		return approvalGrantConsumptionInvalid("grant integrity mismatch")
	}
	grantConsumptionSchema, grantConsumptionContract, ok := approvalGrantConsumptionEnvelope(grant.SchemaVersion)
	if !ok || c.SchemaVersion != grantConsumptionSchema || c.ContractVersion != grantConsumptionContract {
		return approvalGrantConsumptionInvalid("consumption schema does not match the sealed grant")
	}
	if c.ApprovalID != grant.ApprovalID || c.GrantID != grant.GrantID || c.GrantHash != grant.GrantHash ||
		c.TenantID != grant.TenantID || c.WorkspaceID != grant.WorkspaceID || c.Audience != grant.Audience ||
		c.PackID != grant.PackID || c.PackVersion != grant.PackVersion || c.PackManifestHash != grant.PackManifestHash ||
		c.Action != grant.Action || c.IntentHash != grant.IntentHash || c.EffectHash != grant.EffectHash ||
		c.PlanHash != grant.PlanHash || c.PolicyVersion != grant.PolicyVersion || c.PolicyEpoch != grant.PolicyEpoch ||
		c.PolicyHash != grant.PolicyHash || c.ServerIdentity != grant.ServerIdentity ||
		c.KernelTrustRootID != grant.KernelTrustRootID || c.SigningKeyRef != grant.SigningKeyRef ||
		!c.GrantIssuedAt.Equal(grant.IssuedAt) || !c.GrantExpiresAt.Equal(grant.ExpiresAt) {
		return approvalGrantConsumptionInvalid("consumption does not match the sealed grant")
	}
	return nil
}

func approvalGrantConsumptionEnvelope(grantSchemaVersion string) (schemaVersion, contractVersion string, ok bool) {
	switch grantSchemaVersion {
	case ApprovalGrantSchemaV1:
		return ApprovalGrantConsumptionSchemaV1, ApprovalGrantConsumptionContractV1, true
	case ApprovalGrantSchemaV2:
		return ApprovalGrantConsumptionSchemaV2, ApprovalGrantConsumptionContractV2, true
	default:
		return "", "", false
	}
}

func approvalGrantConsumptionInvalid(message string) error {
	return fmt.Errorf("%w: consumption: %s", ErrApprovalGrantIntegrity, message)
}

func isApprovalGrantConsumptionToken(value string) bool {
	return value != "" && strings.IndexFunc(value, unicode.IsSpace) == -1
}
