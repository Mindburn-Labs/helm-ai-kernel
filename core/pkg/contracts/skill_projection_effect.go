package contracts

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SkillProjectionEffectSchemaV1   = "helm.skill-projection-effect.v1"
	SkillProjectionEffectContractV1 = "2026-08-30"

	SkillProjectionActionInstall  = "install"
	SkillProjectionActionReadback = "readback"
	SkillProjectionActionRevoke   = "revoke"
	SkillProjectionActionRollback = "rollback"

	SkillProjectionSandboxProfileV1 = "helm.skill-prompt-projection.v1"

	// SkillProjectionArtifactSchemaHashV1 pins the only V1 artifact shape:
	// the exact UTF-8 prompt and its manifest, with no executable payloads.
	SkillProjectionArtifactSchemaHashV1 = "sha256:366de0c047229bff7c620f3b3a4f2a78bd19880a3d627ec27595e445f45d1b4d"

	SkillProjectionRollbackPermitSchemaV1   = "helm.skill-projection-rollback-permit.v1"
	SkillProjectionRollbackPermitContractV1 = "2026-08-30"

	SkillProjectionConsumedPermitRefSchemaV1 = "helm.skill-projection-consumed-permit-ref.v1"
)

var (
	ErrSkillProjectionEffectInvalid   = errors.New("skill projection effect invalid")
	ErrSkillProjectionEffectInactive  = errors.New("skill projection effect inactive")
	ErrSkillProjectionEffectIntegrity = errors.New("skill projection effect integrity failure")

	skillProjectionScopeIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	skillProjectionSkillIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}/[a-z0-9][a-z0-9-]{0,63}$`)
	skillProjectionHMACPattern    = regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`)
)

// SkillProjectionEffect is the immutable request passed to the repo-scoped
// prompt projection boundary. It is not authority by itself: the caller must
// authenticate and consume the named permit before invoking the lifecycle.
type SkillProjectionEffect struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`
	Action          string `json:"action"`

	TenantID     string `json:"tenant_id"`
	WorkspaceID  string `json:"workspace_id"`
	SkillID      string `json:"skill_id"`
	SkillVersion string `json:"skill_version"`
	AgentTarget  string `json:"agent_target"`

	ArtifactHash string `json:"artifact_hash"`
	ContentHash  string `json:"content_hash"`
	ManifestHash string `json:"manifest_hash"`
	PolicyHash   string `json:"policy_hash"`
	SchemaHash   string `json:"schema_hash"`

	CertificationRefs  []string `json:"certification_refs"`
	ConsumedPermitRef  string   `json:"consumed_permit_ref"`
	RollbackPermitHash string   `json:"rollback_permit_hash,omitempty"`

	IdempotencyKey string `json:"idempotency_key"`
	AttemptID      string `json:"attempt_id"`
	Generation     uint64 `json:"generation"`

	ExpiresAt      time.Time `json:"expires_at"`
	Nonce          string    `json:"nonce"`
	SandboxProfile string    `json:"sandbox_profile"`

	CanonicalRequestHash string `json:"canonical_request_hash,omitempty"`
}

// SkillProjectionRollbackPermit is a separately signed, rollback-only
// authority binding. Seal provides canonical integrity only; the lifecycle
// must authenticate IssuerID, KeyID, and Signature against its pinned keys.
// A general consumed permit cannot be reused as rollback authority, and the
// target generation/artifact are immutable.
type SkillProjectionRollbackPermit struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`
	PermitRef       string `json:"permit_ref"`
	Action          string `json:"action"`

	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	SkillID     string `json:"skill_id"`
	AgentTarget string `json:"agent_target"`

	FromGeneration     uint64 `json:"from_generation"`
	TargetGeneration   uint64 `json:"target_generation"`
	TargetSkillVersion string `json:"target_skill_version"`
	TargetArtifactHash string `json:"target_artifact_hash"`
	TargetPolicyHash   string `json:"target_policy_hash"`

	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Nonce     string    `json:"nonce"`

	IssuerID   string `json:"issuer_id,omitempty"`
	KeyID      string `json:"key_id,omitempty"`
	Signature  string `json:"signature,omitempty"`
	PermitHash string `json:"permit_hash,omitempty"`
}

// ComputeSkillProjectionArtifactHash binds the exact V1 file names and their
// byte hashes. The filesystem lifecycle recomputes both byte hashes before use.
func ComputeSkillProjectionArtifactHash(manifestHash, contentHash string) (string, error) {
	if !isApprovalGrantSHA256(manifestHash) || !isApprovalGrantSHA256(contentHash) {
		return "", skillProjectionEffectInvalid("artifact members must be lowercase sha256 references")
	}
	binding := struct {
		SchemaHash string `json:"schema_hash"`
		Files      []struct {
			Name string `json:"name"`
			Hash string `json:"hash"`
		} `json:"files"`
	}{SchemaHash: SkillProjectionArtifactSchemaHashV1}
	binding.Files = append(binding.Files,
		struct {
			Name string `json:"name"`
			Hash string `json:"hash"`
		}{Name: "skillpack.json", Hash: manifestHash},
		struct {
			Name string `json:"name"`
			Hash string `json:"hash"`
		}{Name: "SKILL.md", Hash: contentHash},
	)
	hash, err := hashJCS(binding)
	if err != nil {
		return "", fmt.Errorf("%w: artifact hash: %v", ErrSkillProjectionEffectInvalid, err)
	}
	return hash, nil
}

// ComputeSkillProjectionConsumedPermitRef derives the permit reference from
// the connector binding committed before the effect is sealed and later
// carried by the signed grant consumption. Keeping this reference independent
// of EffectHash and GrantHash avoids a circular hash dependency.
func ComputeSkillProjectionConsumedPermitRef(tenantID, workspaceID, bindingRef string) (string, error) {
	if !skillProjectionScopeIDPattern.MatchString(tenantID) {
		return "", skillProjectionEffectInvalid("consumed permit tenant_id is not a safe scope identifier")
	}
	if !skillProjectionScopeIDPattern.MatchString(workspaceID) {
		return "", skillProjectionEffectInvalid("consumed permit workspace_id is not a safe scope identifier")
	}
	if !skillProjectionBoundedToken(bindingRef, 512) || !isApprovalGrantToken(bindingRef) {
		return "", skillProjectionEffectInvalid("consumed permit binding_ref must be a bounded token")
	}
	ref, err := hashJCS(struct {
		SchemaVersion string `json:"schema_version"`
		TenantID      string `json:"tenant_id"`
		WorkspaceID   string `json:"workspace_id"`
		BindingRef    string `json:"binding_ref"`
	}{
		SchemaVersion: SkillProjectionConsumedPermitRefSchemaV1,
		TenantID:      tenantID,
		WorkspaceID:   workspaceID,
		BindingRef:    bindingRef,
	})
	if err != nil {
		return "", fmt.Errorf("%w: consumed permit reference: %v", ErrSkillProjectionEffectInvalid, err)
	}
	return ref, nil
}

func (e SkillProjectionEffect) Validate() error {
	if e.SchemaVersion != SkillProjectionEffectSchemaV1 {
		return skillProjectionEffectInvalid("unsupported schema_version")
	}
	if e.ContractVersion != SkillProjectionEffectContractV1 {
		return skillProjectionEffectInvalid("unsupported contract_version")
	}
	switch e.Action {
	case SkillProjectionActionInstall, SkillProjectionActionReadback,
		SkillProjectionActionRevoke, SkillProjectionActionRollback:
	default:
		return skillProjectionEffectInvalid("unsupported action")
	}
	if !skillProjectionScopeIDPattern.MatchString(e.TenantID) {
		return skillProjectionEffectInvalid("tenant_id is not a safe scope identifier")
	}
	if !skillProjectionScopeIDPattern.MatchString(e.WorkspaceID) {
		return skillProjectionEffectInvalid("workspace_id is not a safe scope identifier")
	}
	if !skillProjectionSkillIDPattern.MatchString(e.SkillID) {
		return skillProjectionEffectInvalid("skill_id must be publisher/name")
	}
	if !skillProjectionBoundedToken(e.SkillVersion, 128) {
		return skillProjectionEffectInvalid("skill_version is required and must be a bounded token")
	}
	if !isSkillProjectionAgentTarget(e.AgentTarget) {
		return skillProjectionEffectInvalid("unsupported agent_target")
	}
	for field, value := range map[string]string{
		"artifact_hash": e.ArtifactHash,
		"content_hash":  e.ContentHash,
		"manifest_hash": e.ManifestHash,
		"policy_hash":   e.PolicyHash,
	} {
		if !isApprovalGrantSHA256(value) {
			return skillProjectionEffectInvalid(field + " must be a lowercase sha256 reference")
		}
	}
	if e.SchemaHash != SkillProjectionArtifactSchemaHashV1 {
		return skillProjectionEffectInvalid("schema_hash is not the pinned V1 artifact schema")
	}
	expectedArtifactHash, err := ComputeSkillProjectionArtifactHash(e.ManifestHash, e.ContentHash)
	if err != nil || expectedArtifactHash != e.ArtifactHash {
		return skillProjectionEffectInvalid("artifact_hash does not match manifest/content hashes")
	}
	if err := validateSkillProjectionCertificationRefs(e.CertificationRefs); err != nil {
		return err
	}
	if !isApprovalGrantSHA256(e.ConsumedPermitRef) {
		return skillProjectionEffectInvalid("consumed_permit_ref must be a lowercase sha256 reference")
	}
	if !skillProjectionBoundedToken(e.IdempotencyKey, 512) {
		return skillProjectionEffectInvalid("idempotency_key is required and must be a bounded token")
	}
	if !skillProjectionBoundedToken(e.AttemptID, 512) {
		return skillProjectionEffectInvalid("attempt_id is required and must be a bounded token")
	}
	if e.Generation == 0 || e.Generation > 9007199254740991 {
		return skillProjectionEffectInvalid("generation must be a positive JCS-safe integer")
	}
	if e.ExpiresAt.IsZero() || !isApprovalGrantUTC(e.ExpiresAt) {
		return skillProjectionEffectInvalid("expires_at is required and must use UTC")
	}
	if !isApprovalGrantNonce(e.Nonce) {
		return skillProjectionEffectInvalid("nonce must be 32 lowercase hexadecimal bytes")
	}
	if e.SandboxProfile != SkillProjectionSandboxProfileV1 {
		return skillProjectionEffectInvalid("unsupported sandbox_profile")
	}
	if e.Action == SkillProjectionActionRollback {
		if !isApprovalGrantSHA256(e.RollbackPermitHash) {
			return skillProjectionEffectInvalid("rollback_permit_hash is required for rollback")
		}
	} else if e.RollbackPermitHash != "" {
		return skillProjectionEffectInvalid("rollback_permit_hash is only valid for rollback")
	}
	if e.CanonicalRequestHash != "" && !isApprovalGrantSHA256(e.CanonicalRequestHash) {
		return skillProjectionEffectInvalid("canonical_request_hash must be a lowercase sha256 reference")
	}
	return nil
}

func (e SkillProjectionEffect) Seal() (SkillProjectionEffect, error) {
	if err := e.Validate(); err != nil {
		return SkillProjectionEffect{}, err
	}
	e.CanonicalRequestHash = ""
	hash, err := hashJCS(e)
	if err != nil {
		return SkillProjectionEffect{}, fmt.Errorf("%w: seal: %v", ErrSkillProjectionEffectInvalid, err)
	}
	e.CanonicalRequestHash = hash
	return e, nil
}

func (e SkillProjectionEffect) ValidateAt(now time.Time) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if e.CanonicalRequestHash == "" {
		return fmt.Errorf("%w: canonical_request_hash is required", ErrSkillProjectionEffectIntegrity)
	}
	sealed, err := e.Seal()
	if err != nil || sealed.CanonicalRequestHash != e.CanonicalRequestHash {
		return fmt.Errorf("%w: canonical_request_hash mismatch", ErrSkillProjectionEffectIntegrity)
	}
	if !now.Before(e.ExpiresAt) {
		return fmt.Errorf("%w: request is expired", ErrSkillProjectionEffectInactive)
	}
	return nil
}

func (p SkillProjectionRollbackPermit) Validate() error {
	if p.SchemaVersion != SkillProjectionRollbackPermitSchemaV1 {
		return skillProjectionEffectInvalid("rollback permit has unsupported schema_version")
	}
	if p.ContractVersion != SkillProjectionRollbackPermitContractV1 {
		return skillProjectionEffectInvalid("rollback permit has unsupported contract_version")
	}
	if !isApprovalGrantSHA256(p.PermitRef) {
		return skillProjectionEffectInvalid("rollback permit_ref must be a lowercase sha256 reference")
	}
	if p.Action != SkillProjectionActionRollback {
		return skillProjectionEffectInvalid("rollback permit action must be rollback")
	}
	if !skillProjectionScopeIDPattern.MatchString(p.TenantID) ||
		!skillProjectionScopeIDPattern.MatchString(p.WorkspaceID) ||
		!skillProjectionSkillIDPattern.MatchString(p.SkillID) ||
		!isSkillProjectionAgentTarget(p.AgentTarget) {
		return skillProjectionEffectInvalid("rollback permit scope is invalid")
	}
	if p.FromGeneration == 0 || p.TargetGeneration == 0 ||
		p.FromGeneration > 9007199254740991 || p.TargetGeneration >= p.FromGeneration {
		return skillProjectionEffectInvalid("rollback generations are invalid")
	}
	if !skillProjectionBoundedToken(p.TargetSkillVersion, 128) {
		return skillProjectionEffectInvalid("rollback target_skill_version is invalid")
	}
	if !isApprovalGrantSHA256(p.TargetArtifactHash) || !isApprovalGrantSHA256(p.TargetPolicyHash) {
		return skillProjectionEffectInvalid("rollback target hashes must be lowercase sha256 references")
	}
	if p.IssuedAt.IsZero() || p.ExpiresAt.IsZero() ||
		!isApprovalGrantUTC(p.IssuedAt) || !isApprovalGrantUTC(p.ExpiresAt) ||
		!p.ExpiresAt.After(p.IssuedAt) {
		return skillProjectionEffectInvalid("rollback permit lifetime is invalid")
	}
	if !isApprovalGrantNonce(p.Nonce) {
		return skillProjectionEffectInvalid("rollback permit nonce must be 32 lowercase hexadecimal bytes")
	}
	if (p.IssuerID == "") != (p.KeyID == "") {
		return skillProjectionEffectInvalid("rollback permit issuer_id and key_id must be supplied together")
	}
	if p.IssuerID != "" && (!skillProjectionBoundedToken(p.IssuerID, 128) || !skillProjectionBoundedToken(p.KeyID, 128)) {
		return skillProjectionEffectInvalid("rollback permit issuer/key identity is invalid")
	}
	if p.Signature != "" && (p.IssuerID == "" || !skillProjectionHMACPattern.MatchString(p.Signature)) {
		return skillProjectionEffectInvalid("rollback permit signature is invalid")
	}
	if p.PermitHash != "" && !isApprovalGrantSHA256(p.PermitHash) {
		return skillProjectionEffectInvalid("rollback permit_hash must be a lowercase sha256 reference")
	}
	return nil
}

func (p SkillProjectionRollbackPermit) Seal() (SkillProjectionRollbackPermit, error) {
	if err := p.Validate(); err != nil {
		return SkillProjectionRollbackPermit{}, err
	}
	p.PermitHash = ""
	p.Signature = ""
	hash, err := hashJCS(p)
	if err != nil {
		return SkillProjectionRollbackPermit{}, fmt.Errorf("%w: rollback permit seal: %v", ErrSkillProjectionEffectInvalid, err)
	}
	p.PermitHash = hash
	return p, nil
}

func (p SkillProjectionRollbackPermit) ValidateAt(now time.Time) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.PermitHash == "" {
		return fmt.Errorf("%w: rollback permit_hash is required", ErrSkillProjectionEffectIntegrity)
	}
	sealed, err := p.Seal()
	if err != nil || sealed.PermitHash != p.PermitHash {
		return fmt.Errorf("%w: rollback permit_hash mismatch", ErrSkillProjectionEffectIntegrity)
	}
	if now.Before(p.IssuedAt) || !now.Before(p.ExpiresAt) {
		return fmt.Errorf("%w: rollback permit is not active", ErrSkillProjectionEffectInactive)
	}
	return nil
}

// ValidateRollbackPermit proves that the canonical rollback permit names this
// exact effect. It does not authenticate the permit issuer; the filesystem
// lifecycle owns signature verification plus current-generation and archive
// existence checks.
func (e SkillProjectionEffect) ValidateRollbackPermit(p SkillProjectionRollbackPermit, now time.Time) error {
	if e.Action != SkillProjectionActionRollback {
		return skillProjectionEffectInvalid("effect action is not rollback")
	}
	if err := p.ValidateAt(now); err != nil {
		return err
	}
	if p.PermitHash != e.RollbackPermitHash || p.PermitRef == e.ConsumedPermitRef ||
		p.TenantID != e.TenantID || p.WorkspaceID != e.WorkspaceID ||
		p.SkillID != e.SkillID || p.AgentTarget != e.AgentTarget ||
		p.TargetSkillVersion != e.SkillVersion || p.TargetArtifactHash != e.ArtifactHash ||
		p.TargetPolicyHash != e.PolicyHash || e.Generation != p.FromGeneration+1 {
		return skillProjectionEffectInvalid("rollback permit does not match the effect")
	}
	return nil
}

func validateSkillProjectionCertificationRefs(refs []string) error {
	if len(refs) == 0 || len(refs) > 16 {
		return skillProjectionEffectInvalid("certification_refs must contain 1 to 16 entries")
	}
	previous := ""
	for _, ref := range refs {
		if !skillProjectionBoundedToken(ref, 512) {
			return skillProjectionEffectInvalid("certification_refs must be bounded tokens")
		}
		if previous != "" && strings.Compare(previous, ref) >= 0 {
			return skillProjectionEffectInvalid("certification_refs must be sorted and unique")
		}
		previous = ref
	}
	return nil
}

func skillProjectionBoundedToken(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && strings.IndexFunc(value, func(r rune) bool {
		return r == 0 || r == '\u007f' || r == '\u2028' || r == '\u2029' ||
			r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) == -1
}

func isSkillProjectionAgentTarget(value string) bool {
	switch value {
	case "codex", "claude-code", "cursor", "opencode":
		return true
	default:
		return false
	}
}

func skillProjectionEffectInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrSkillProjectionEffectInvalid, message)
}
