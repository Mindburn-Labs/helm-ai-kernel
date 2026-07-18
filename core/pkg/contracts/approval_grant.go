package contracts

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const (
	ApprovalGrantSchemaV1   = "approval-grant.v1"
	ApprovalGrantContractV1 = "2026-07-15"
	ApprovalGrantSchemaV2   = "approval-grant.v2"
	ApprovalGrantContractV2 = "2026-07-18"

	ApprovalGrantDecisionAllow = "ALLOW"

	ApprovalGrantActionInstall   = "install"
	ApprovalGrantActionUpgrade   = "upgrade"
	ApprovalGrantActionUninstall = "uninstall"
	ApprovalGrantActionRollback  = "rollback"

	// ApprovalGrantActionPolicyDraftSandbox is intentionally the only
	// non-lifecycle action admitted by the versioned V2 envelope.
	ApprovalGrantActionPolicyDraftSandbox = "policy.draft.sandbox"

	// ApprovalGrantAudiencePolicyDraftSandboxExecutorV1 and
	// ApprovalGrantPackIDPolicyDraftSandbox fence V2 to its dedicated consumer.
	ApprovalGrantAudiencePolicyDraftSandboxExecutorV1 = "helm.policy-draft-sandbox.executor.v1"
	ApprovalGrantPackIDPolicyDraftSandbox             = "helm.policy-draft-sandbox"
)

var (
	ErrApprovalGrantInvalid   = errors.New("approval grant invalid")
	ErrApprovalGrantInactive  = errors.New("approval grant inactive")
	ErrApprovalGrantIntegrity = errors.New("approval grant integrity failure")
)

// ApprovalGrant is the source-owned binding for a future, server-signed,
// single-use approval authority. It is deliberately not an authorization on
// its own: callers MUST verify the server signature and atomically consume the
// grant in a durable store before performing a mutation.
//
// V2 introduces no duplicate release or binding fields: PackID, PackVersion,
// PackManifestHash, IntentHash, EffectHash, and PlanHash remain the complete
// portable, signed binding tuple. The ceremony's BindingRef stays internal to
// its source-owned durable record and commitment.
//
// GrantHash seals every authority-bearing field below. The approvalceremony
// boundary owns its signature, durable single-use transition, and the separate
// signed ApprovalGrantConsumption record; legacy approval metadata MUST NOT be
// promoted into this contract.
type ApprovalGrant struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`

	GrantID     string `json:"grant_id"`
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

	ApprovalID    string `json:"approval_id"`
	CeremonyHash  string `json:"ceremony_hash"`
	SignerSetHash string `json:"signer_set_hash"`

	ServerIdentity    string `json:"server_identity"`
	KernelTrustRootID string `json:"kernel_trust_root_id"`
	SigningKeyRef     string `json:"signing_key_ref"`

	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Nonce     string    `json:"nonce"`

	GrantHash string `json:"grant_hash,omitempty"`
}

// Validate checks the immutable grant shape. It does not establish signature
// trust, liveness, or replay safety.
func (g ApprovalGrant) Validate() error {
	switch g.SchemaVersion {
	case ApprovalGrantSchemaV1:
		if g.ContractVersion != ApprovalGrantContractV1 {
			return approvalGrantInvalid("unsupported contract_version")
		}
	case ApprovalGrantSchemaV2:
		if g.ContractVersion != ApprovalGrantContractV2 {
			return approvalGrantInvalid("unsupported contract_version")
		}
	default:
		return approvalGrantInvalid("unsupported schema_version")
	}

	required := []struct {
		field string
		value string
	}{
		{field: "grant_id", value: g.GrantID},
		{field: "tenant_id", value: g.TenantID},
		{field: "workspace_id", value: g.WorkspaceID},
		{field: "audience", value: g.Audience},
		{field: "pack_id", value: g.PackID},
		{field: "pack_version", value: g.PackVersion},
		{field: "policy_version", value: g.PolicyVersion},
		{field: "policy_epoch", value: g.PolicyEpoch},
		{field: "approval_id", value: g.ApprovalID},
		{field: "server_identity", value: g.ServerIdentity},
		{field: "kernel_trust_root_id", value: g.KernelTrustRootID},
		{field: "signing_key_ref", value: g.SigningKeyRef},
	}
	for _, item := range required {
		if !isApprovalGrantToken(item.value) {
			return approvalGrantInvalid(item.field + " is required and must not contain whitespace")
		}
	}

	hashes := []struct {
		field string
		value string
	}{
		{field: "pack_manifest_hash", value: g.PackManifestHash},
		{field: "intent_hash", value: g.IntentHash},
		{field: "effect_hash", value: g.EffectHash},
		{field: "plan_hash", value: g.PlanHash},
		{field: "policy_hash", value: g.PolicyHash},
		{field: "ceremony_hash", value: g.CeremonyHash},
		{field: "signer_set_hash", value: g.SignerSetHash},
	}
	for _, item := range hashes {
		if !isApprovalGrantSHA256(item.value) {
			return approvalGrantInvalid(item.field + " must be a lowercase sha256 reference")
		}
	}

	if err := validateApprovalGrantActionScope(g.SchemaVersion, g.Audience, g.PackID, g.Action); err != nil {
		return approvalGrantInvalid(err.Error())
	}
	if g.Decision != ApprovalGrantDecisionAllow {
		return approvalGrantInvalid("decision must be ALLOW")
	}
	if g.IssuedAt.IsZero() || g.ExpiresAt.IsZero() {
		return approvalGrantInvalid("issued_at and expires_at are required")
	}
	if !isApprovalGrantUTC(g.IssuedAt) || !isApprovalGrantUTC(g.ExpiresAt) {
		return approvalGrantInvalid("issued_at and expires_at must use UTC")
	}
	if !g.ExpiresAt.After(g.IssuedAt) {
		return approvalGrantInvalid("expires_at must be after issued_at")
	}
	if !isApprovalGrantNonce(g.Nonce) {
		return approvalGrantInvalid("nonce must be 32 lowercase hexadecimal bytes")
	}
	if g.GrantHash != "" && !isApprovalGrantSHA256(g.GrantHash) {
		return approvalGrantInvalid("grant_hash must be a lowercase sha256 reference")
	}
	return nil
}

// Seal deterministically hashes the JCS representation of every bound field.
// Seal does not sign or authorize the grant.
func (g ApprovalGrant) Seal() (ApprovalGrant, error) {
	if err := g.Validate(); err != nil {
		return ApprovalGrant{}, err
	}
	g.GrantHash = ""
	hash, err := hashJCS(g)
	if err != nil {
		return ApprovalGrant{}, fmt.Errorf("%w: seal: %v", ErrApprovalGrantInvalid, err)
	}
	g.GrantHash = hash
	return g, nil
}

// ValidateAt checks deterministic integrity and whether the sealed grant is
// active at now. It still does not verify a server signature or consume replay
// state, so success MUST NOT be treated as mutation authority.
func (g ApprovalGrant) ValidateAt(now time.Time) error {
	if err := g.Validate(); err != nil {
		return err
	}
	if g.GrantHash == "" {
		return fmt.Errorf("%w: grant_hash is required", ErrApprovalGrantIntegrity)
	}
	sealed, err := g.Seal()
	if err != nil {
		return err
	}
	if sealed.GrantHash != g.GrantHash {
		return fmt.Errorf("%w: grant_hash mismatch", ErrApprovalGrantIntegrity)
	}
	if now.Before(g.IssuedAt) {
		return fmt.Errorf("%w: grant is not yet active", ErrApprovalGrantInactive)
	}
	if !now.Before(g.ExpiresAt) {
		return fmt.Errorf("%w: grant is expired", ErrApprovalGrantInactive)
	}
	return nil
}

func approvalGrantInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrApprovalGrantInvalid, message)
}

func isApprovalGrantToken(value string) bool {
	return value != "" && strings.IndexFunc(value, unicode.IsSpace) == -1
}

func isApprovalGrantSHA256(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	digest := strings.TrimPrefix(value, prefix)
	if len(digest) != 64 || strings.ToLower(digest) != digest {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == 32
}

func isApprovalGrantNonce(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func isApprovalGrantUTC(value time.Time) bool {
	_, offset := value.Zone()
	return offset == 0
}

func validateApprovalGrantActionScope(schemaVersion, audience, packID, action string) error {
	switch schemaVersion {
	case ApprovalGrantSchemaV1:
		switch action {
		case ApprovalGrantActionInstall,
			ApprovalGrantActionUpgrade,
			ApprovalGrantActionUninstall,
			ApprovalGrantActionRollback:
			return nil
		default:
			return errors.New("unsupported action")
		}
	case ApprovalGrantSchemaV2:
		if action != ApprovalGrantActionPolicyDraftSandbox {
			return errors.New("v2 action must be policy.draft.sandbox")
		}
		if audience != ApprovalGrantAudiencePolicyDraftSandboxExecutorV1 {
			return errors.New("v2 audience is unsupported")
		}
		if packID != ApprovalGrantPackIDPolicyDraftSandbox {
			return errors.New("v2 pack_id is unsupported")
		}
		return nil
	default:
		return errors.New("unsupported schema_version")
	}
}
