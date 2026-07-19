// quantum_posture: approval grant signatures in this lifecycle are classical
// Ed25519 only until a source-owned hybrid contract is introduced.
// Package approvalceremony owns the durable, single-writer lifecycle that turns
// a verified human quorum into a single-use approval grant.
package approvalceremony

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type State string

const (
	StateHoldPending      State = "HOLD_PENDING"
	StateChallengeIssued  State = "CHALLENGE_ISSUED"
	StateQuorumVerified   State = "QUORUM_VERIFIED"
	StateGrantIssued      State = "GRANT_ISSUED"
	StateConsumed         State = "CONSUMED"
	StateExpired          State = "EXPIRED"
	StateDenied           State = "DENIED"
	GrantSignatureEd25519       = "ed25519"
)

var (
	ErrInvalidRecord       = errors.New("approval ceremony record invalid")
	ErrNotFound            = errors.New("approval ceremony not found")
	ErrTransitionConflict  = errors.New("approval ceremony transition conflict")
	ErrEmergencyStopFenced = errors.New("approval ceremony scope is emergency-stop fenced")
)

// Record is the Kernel-owned durable approval lifecycle. Client submissions
// may supply assertions, but never this record or its state transitions.
type Record struct {
	ApprovalID  string `json:"approval_id"`
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	State       State  `json:"state"`

	HoldStartedAt    time.Time                           `json:"hold_started_at"`
	Spec             ChallengeSpec                       `json:"challenge_spec"`
	Challenge        *contracts.ApprovalChallenge        `json:"challenge,omitempty"`
	VerifiedRef      *approvalverify.VerifiedApprovalRef `json:"verified_ref,omitempty"`
	Grant            *contracts.ApprovalGrant            `json:"grant,omitempty"`
	GrantConsumption *contracts.ApprovalGrantConsumption `json:"grant_consumption,omitempty"`

	GrantSignatureAlgorithm       string `json:"grant_signature_algorithm,omitempty"`
	GrantSignature                string `json:"grant_signature,omitempty"`
	ConsumptionSignatureAlgorithm string `json:"consumption_signature_algorithm,omitempty"`
	ConsumptionSignature          string `json:"consumption_signature,omitempty"`

	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
	ConsumedBy string     `json:"consumed_by,omitempty"`
	Version    int64      `json:"version"`
}

// ChallengeSpec is the policy-owned effect context committed before the hold
// starts. Challenge IDs, nonce, timestamps, and hashes are intentionally absent
// because the Kernel creates them after the hold has elapsed.
type ChallengeSpec struct {
	BindingRef            string `json:"binding_ref"`
	TenantID              string `json:"tenant_id"`
	WorkspaceID           string `json:"workspace_id"`
	Audience              string `json:"audience"`
	PackID                string `json:"pack_id"`
	PackVersion           string `json:"pack_version"`
	PackManifestHash      string `json:"pack_manifest_hash"`
	Action                string `json:"action"`
	IntentHash            string `json:"intent_hash"`
	EffectHash            string `json:"effect_hash"`
	PlanHash              string `json:"plan_hash"`
	Decision              string `json:"decision"`
	PolicyVersion         string `json:"policy_version"`
	PolicyEpoch           string `json:"policy_epoch"`
	PolicyHash            string `json:"policy_hash"`
	AuthoritySource       string `json:"authority_source"`
	AuthorityVersion      string `json:"authority_version"`
	AuthoritySnapshotHash string `json:"authority_snapshot_hash"`
	RequiredRole          string `json:"required_role"`
	Quorum                int    `json:"quorum"`
	ServerIdentity        string `json:"server_identity"`
}

func (s ChallengeSpec) Validate() error {
	for field, value := range map[string]string{
		"binding_ref": s.BindingRef, "tenant_id": s.TenantID,
		"workspace_id": s.WorkspaceID, "audience": s.Audience,
		"pack_id": s.PackID, "pack_version": s.PackVersion, "policy_version": s.PolicyVersion,
		"policy_epoch": s.PolicyEpoch, "authority_source": s.AuthoritySource,
		"authority_version": s.AuthorityVersion, "required_role": s.RequiredRole,
		"server_identity": s.ServerIdentity,
	} {
		if !validToken(value) {
			return invalidRecord("challenge_spec " + field + " is invalid")
		}
	}
	for field, value := range map[string]string{
		"pack_manifest_hash": s.PackManifestHash, "intent_hash": s.IntentHash,
		"effect_hash": s.EffectHash, "plan_hash": s.PlanHash, "policy_hash": s.PolicyHash,
		"authority_snapshot_hash": s.AuthoritySnapshotHash,
	} {
		if !validSHA256(value) {
			return invalidRecord("challenge_spec " + field + " is invalid")
		}
	}
	if s.Decision != contracts.ApprovalGrantDecisionAllow || s.Quorum <= 0 {
		return invalidRecord("challenge_spec decision and quorum are invalid")
	}
	switch s.Action {
	case contracts.ApprovalGrantActionInstall, contracts.ApprovalGrantActionUpgrade,
		contracts.ApprovalGrantActionUninstall, contracts.ApprovalGrantActionRollback:
	default:
		return invalidRecord("challenge_spec action is unsupported")
	}
	return nil
}

func (s State) Valid() bool {
	switch s {
	case StateHoldPending, StateChallengeIssued, StateQuorumVerified,
		StateGrantIssued, StateConsumed, StateExpired, StateDenied:
		return true
	default:
		return false
	}
}

// Validate checks the persisted lifecycle projection. It does not verify the
// grant signature; signature verification and atomic consumption are separate
// mandatory gates at the execution boundary.
func (r Record) Validate() error {
	for field, value := range map[string]string{
		"approval_id":  r.ApprovalID,
		"tenant_id":    r.TenantID,
		"workspace_id": r.WorkspaceID,
	} {
		if !validToken(value) {
			return invalidRecord(field + " is required and must not contain whitespace")
		}
	}
	if !r.State.Valid() {
		return invalidRecord("unsupported state")
	}
	if r.HoldStartedAt.IsZero() || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() {
		return invalidRecord("hold_started_at, created_at, and updated_at are required")
	}
	if !isUTC(r.HoldStartedAt) || !isUTC(r.CreatedAt) || !isUTC(r.UpdatedAt) {
		return invalidRecord("timestamps must use UTC")
	}
	if r.UpdatedAt.Before(r.CreatedAt) || r.Version <= 0 {
		return invalidRecord("updated_at and version are invalid")
	}
	if !r.CreatedAt.Equal(r.HoldStartedAt) {
		return invalidRecord("created_at must equal hold_started_at")
	}
	if r.ExpiresAt != nil && !isUTC(*r.ExpiresAt) {
		return invalidRecord("expires_at must use UTC")
	}
	if err := r.Spec.Validate(); err != nil {
		return err
	}
	if r.Spec.TenantID != r.TenantID || r.Spec.WorkspaceID != r.WorkspaceID {
		return invalidRecord("challenge_spec record scope mismatch")
	}

	if r.Challenge != nil {
		if err := validateChallenge(r, *r.Challenge); err != nil {
			return err
		}
	}
	if r.VerifiedRef != nil {
		if r.Challenge == nil {
			return invalidRecord("verified_ref requires challenge")
		}
		if err := validateVerifiedRef(*r.Challenge, *r.VerifiedRef); err != nil {
			return err
		}
	}
	if r.Grant != nil {
		if r.VerifiedRef == nil {
			return invalidRecord("grant requires verified_ref")
		}
		if err := validateGrant(*r.Challenge, *r.VerifiedRef, *r.Grant); err != nil {
			return err
		}
		ceremonyHash, err := CeremonyCommitment(r)
		if err != nil || ceremonyHash != r.Grant.CeremonyHash {
			return invalidRecord("grant ceremony commitment mismatch")
		}
		if r.GrantSignatureAlgorithm != GrantSignatureEd25519 {
			return invalidRecord("grant signature algorithm must be ed25519")
		}
		if !validEd25519Signature(r.GrantSignature) {
			return invalidRecord("grant signature must be 64 lowercase hexadecimal bytes")
		}
	} else if r.GrantSignatureAlgorithm != "" || r.GrantSignature != "" {
		return invalidRecord("grant signature requires grant")
	}
	if r.GrantConsumption != nil {
		if r.Grant == nil {
			return invalidRecord("grant_consumption requires grant")
		}
		if err := r.GrantConsumption.ValidateGrant(*r.Grant); err != nil {
			return invalidRecord("grant_consumption: " + err.Error())
		}
		if r.ConsumptionSignatureAlgorithm != GrantSignatureEd25519 {
			return invalidRecord("consumption signature algorithm must be ed25519")
		}
		if !validEd25519Signature(r.ConsumptionSignature) {
			return invalidRecord("consumption signature must be 64 lowercase hexadecimal bytes")
		}
	} else if r.ConsumptionSignatureAlgorithm != "" || r.ConsumptionSignature != "" {
		return invalidRecord("consumption signature requires grant_consumption")
	}

	switch r.State {
	case StateHoldPending:
		if r.Challenge != nil || r.VerifiedRef != nil || r.Grant != nil {
			return invalidRecord("hold pending cannot contain authority artifacts")
		}
		if !r.UpdatedAt.Equal(r.HoldStartedAt) {
			return invalidRecord("hold pending updated_at must equal hold_started_at")
		}
		if r.ExpiresAt != nil {
			return invalidRecord("hold pending cannot have expires_at")
		}
	case StateChallengeIssued:
		if r.Challenge == nil || r.VerifiedRef != nil || r.Grant != nil {
			return invalidRecord("challenge issued requires only challenge")
		}
		if !r.UpdatedAt.Equal(r.Challenge.IssuedAt) {
			return invalidRecord("challenge issued updated_at mismatch")
		}
		if r.ExpiresAt == nil || !r.ExpiresAt.Equal(r.Challenge.ExpiresAt) {
			return invalidRecord("challenge expires_at shadow mismatch")
		}
	case StateQuorumVerified:
		if r.Challenge == nil || r.VerifiedRef == nil || r.Grant != nil {
			return invalidRecord("quorum verified requires challenge and verified_ref")
		}
		if !r.UpdatedAt.Equal(r.VerifiedRef.VerifiedAt) {
			return invalidRecord("quorum verified updated_at mismatch")
		}
		if r.ExpiresAt == nil || !r.ExpiresAt.Equal(r.Challenge.ExpiresAt) {
			return invalidRecord("verified expires_at shadow mismatch")
		}
	case StateGrantIssued:
		if r.Challenge == nil || r.VerifiedRef == nil || r.Grant == nil {
			return invalidRecord("grant issued requires complete authority chain")
		}
		if !r.UpdatedAt.Equal(r.Grant.IssuedAt) {
			return invalidRecord("grant issued updated_at mismatch")
		}
		if r.ExpiresAt == nil || !r.ExpiresAt.Equal(r.Grant.ExpiresAt) {
			return invalidRecord("grant expires_at shadow mismatch")
		}
	case StateConsumed:
		if r.Grant == nil || r.GrantConsumption == nil || r.ConsumedAt == nil || !validToken(r.ConsumedBy) {
			return invalidRecord("consumed requires grant, grant_consumption, consumed_at, and consumed_by")
		}
		if !isUTC(*r.ConsumedAt) || !r.ConsumedAt.Equal(r.UpdatedAt) {
			return invalidRecord("consumed_at is invalid")
		}
		if r.ConsumedAt.Before(r.Grant.IssuedAt) || !r.ConsumedAt.Before(r.Grant.ExpiresAt) {
			return invalidRecord("consumed_at is outside the signed grant lifetime")
		}
		if r.ExpiresAt == nil || !r.ExpiresAt.Equal(r.Grant.ExpiresAt) {
			return invalidRecord("consumed expires_at shadow mismatch")
		}
		if r.GrantConsumption.ConsumedBy != r.ConsumedBy || !r.GrantConsumption.ConsumedAt.Equal(*r.ConsumedAt) {
			return invalidRecord("consumption record shadow mismatch")
		}
	case StateExpired, StateDenied:
		if r.GrantConsumption != nil || r.ConsumedAt != nil || r.ConsumedBy != "" {
			return invalidRecord("terminal non-consumed state cannot contain consumption")
		}
		if r.Grant != nil && (r.ExpiresAt == nil || !r.ExpiresAt.Equal(r.Grant.ExpiresAt)) {
			return invalidRecord("terminal grant expires_at shadow mismatch")
		}
		if r.Grant == nil && r.Challenge != nil && (r.ExpiresAt == nil || !r.ExpiresAt.Equal(r.Challenge.ExpiresAt)) {
			return invalidRecord("terminal challenge expires_at shadow mismatch")
		}
		if r.State == StateExpired && (r.Challenge == nil || r.ExpiresAt == nil || r.UpdatedAt.Before(*r.ExpiresAt)) {
			return invalidRecord("expired transition precedes committed expiry")
		}
	}
	if r.State != StateConsumed && (r.GrantConsumption != nil || r.ConsumptionSignatureAlgorithm != "" ||
		r.ConsumptionSignature != "" || r.ConsumedAt != nil || r.ConsumedBy != "") {
		return invalidRecord("consumption fields require consumed state")
	}
	return nil
}

func validateChallenge(record Record, challenge contracts.ApprovalChallenge) error {
	if err := challenge.Validate(); err != nil {
		return invalidRecord("challenge: " + err.Error())
	}
	if challenge.ChallengeHash == "" {
		return invalidRecord("challenge_hash is required")
	}
	sealed, err := challenge.Seal()
	if err != nil || sealed.ChallengeHash != challenge.ChallengeHash {
		return invalidRecord("challenge integrity mismatch")
	}
	if challenge.ApprovalID != record.ApprovalID || challenge.TenantID != record.TenantID || challenge.WorkspaceID != record.WorkspaceID {
		return invalidRecord("challenge scope mismatch")
	}
	if !challenge.HoldStartedAt.Equal(record.HoldStartedAt) {
		return invalidRecord("challenge hold_started_at mismatch")
	}
	spec := record.Spec
	if challenge.TenantID != spec.TenantID || challenge.WorkspaceID != spec.WorkspaceID ||
		challenge.Audience != spec.Audience || challenge.PackID != spec.PackID ||
		challenge.PackVersion != spec.PackVersion || challenge.PackManifestHash != spec.PackManifestHash ||
		challenge.Action != spec.Action || challenge.IntentHash != spec.IntentHash ||
		challenge.EffectHash != spec.EffectHash || challenge.PlanHash != spec.PlanHash ||
		challenge.Decision != spec.Decision || challenge.PolicyVersion != spec.PolicyVersion ||
		challenge.PolicyEpoch != spec.PolicyEpoch || challenge.PolicyHash != spec.PolicyHash ||
		challenge.AuthoritySource != spec.AuthoritySource || challenge.AuthorityVersion != spec.AuthorityVersion ||
		challenge.AuthoritySnapshotHash != spec.AuthoritySnapshotHash || challenge.RequiredRole != spec.RequiredRole ||
		challenge.Quorum != spec.Quorum || challenge.ServerIdentity != spec.ServerIdentity {
		return invalidRecord("challenge does not match committed challenge_spec")
	}
	return nil
}

func validateVerifiedRef(challenge contracts.ApprovalChallenge, verified approvalverify.VerifiedApprovalRef) error {
	if verified.ApprovalID != challenge.ApprovalID || verified.ChallengeID != challenge.ChallengeID ||
		verified.ChallengeHash != challenge.ChallengeHash || verified.TenantID != challenge.TenantID ||
		verified.WorkspaceID != challenge.WorkspaceID || verified.Audience != challenge.Audience ||
		verified.PackID != challenge.PackID || verified.PackVersion != challenge.PackVersion ||
		verified.PackManifestHash != challenge.PackManifestHash || verified.Action != challenge.Action ||
		verified.IntentHash != challenge.IntentHash || verified.EffectHash != challenge.EffectHash ||
		verified.PlanHash != challenge.PlanHash || verified.Decision != challenge.Decision ||
		verified.PolicyVersion != challenge.PolicyVersion || verified.PolicyEpoch != challenge.PolicyEpoch ||
		verified.PolicyHash != challenge.PolicyHash || verified.AuthoritySource != challenge.AuthoritySource ||
		verified.AuthorityVersion != challenge.AuthorityVersion || verified.AuthoritySnapshotHash != challenge.AuthoritySnapshotHash ||
		verified.ServerIdentity != challenge.ServerIdentity || verified.RequiredRole != challenge.RequiredRole ||
		verified.Quorum != challenge.Quorum {
		return invalidRecord("verified_ref binding mismatch")
	}
	if len(verified.Signers) < challenge.Quorum || !validSHA256(verified.SignerSetHash) || verified.VerifiedAt.IsZero() || !isUTC(verified.VerifiedAt) {
		return invalidRecord("verified_ref quorum evidence is invalid")
	}
	if verified.VerifiedAt.Before(challenge.IssuedAt) || !verified.VerifiedAt.Before(challenge.ExpiresAt) {
		return invalidRecord("verified_ref timestamp is outside the challenge lifetime")
	}
	return nil
}

func validateGrant(challenge contracts.ApprovalChallenge, verified approvalverify.VerifiedApprovalRef, grant contracts.ApprovalGrant) error {
	if err := grant.Validate(); err != nil {
		return invalidRecord("grant: " + err.Error())
	}
	if grant.GrantHash == "" {
		return invalidRecord("grant_hash is required")
	}
	sealed, err := grant.Seal()
	if err != nil || sealed.GrantHash != grant.GrantHash {
		return invalidRecord("grant integrity mismatch")
	}
	if grant.ApprovalID != verified.ApprovalID || grant.TenantID != verified.TenantID ||
		grant.WorkspaceID != verified.WorkspaceID || grant.Audience != verified.Audience ||
		grant.PackID != verified.PackID || grant.PackVersion != verified.PackVersion ||
		grant.PackManifestHash != verified.PackManifestHash || grant.Action != verified.Action ||
		grant.IntentHash != verified.IntentHash || grant.EffectHash != verified.EffectHash ||
		grant.PlanHash != verified.PlanHash || grant.Decision != verified.Decision ||
		grant.PolicyVersion != verified.PolicyVersion || grant.PolicyEpoch != verified.PolicyEpoch ||
		grant.PolicyHash != verified.PolicyHash || grant.SignerSetHash != verified.SignerSetHash ||
		grant.ServerIdentity != verified.ServerIdentity {
		return invalidRecord("grant binding mismatch")
	}
	if grant.IssuedAt.Before(verified.VerifiedAt) || grant.ExpiresAt.After(challenge.ExpiresAt) {
		return invalidRecord("grant lifetime exceeds the verified ceremony")
	}
	return nil
}

func validToken(value string) bool {
	return value != "" && strings.IndexFunc(value, unicode.IsSpace) == -1
}

func validSHA256(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	raw := strings.TrimPrefix(value, prefix)
	if len(raw) != 64 || strings.ToLower(raw) != raw {
		return false
	}
	decoded, err := hex.DecodeString(raw)
	return err == nil && len(decoded) == 32
}

func validEd25519Signature(value string) bool {
	if len(value) != 128 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 64
}

func isUTC(value time.Time) bool {
	_, offset := value.Zone()
	return offset == 0
}

func invalidRecord(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidRecord, message)
}
