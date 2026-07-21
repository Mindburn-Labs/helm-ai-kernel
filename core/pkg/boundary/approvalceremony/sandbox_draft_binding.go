package approvalceremony

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	SandboxDraftProposalSchemaV1   = "sandbox-draft-proposal.v1"
	SandboxDraftProposalContractV1 = "2026-07-18"
)

var ErrSandboxDraftProposalInvalid = errors.New("sandbox draft proposal invalid")

// SandboxDraftProposal is the immutable source record for the one V2 approval
// scope. Canonical JSON and their hashes are both required so the provider can
// reject any source/store drift before a hold is persisted.
//
// It deliberately has no action, audience, pack ID, or decision field. Those
// are fixed by the Kernel when the binding is derived.
type SandboxDraftProposal struct {
	SchemaVersion   string
	ContractVersion string

	BindingRef     string
	ProposalID     string
	TenantID       string
	WorkspaceID    string
	Subject        string
	TemplateID     string
	TemplateDigest string

	PlanCanonicalJSON   []byte
	PlanHash            string
	IntentCanonicalJSON []byte
	IntentHash          string
	EffectCanonicalJSON []byte
	EffectHash          string

	PackVersion      string
	PackManifestHash string
	PolicyVersion    string
	PolicyEpoch      string
	PolicyHash       string

	AuthoritySource       string
	AuthorityVersion      string
	AuthoritySnapshotHash string
	RequiredRole          string
	Quorum                int
	ServerIdentity        string
}

// SandboxDraftProposalSource is the only integration seam for the H142 draft
// proposal record. Implementations must load an immutable source-owned record;
// this package does not provide transport, approval authority, or dispatch.
type SandboxDraftProposalSource interface {
	LoadSandboxDraftProposal(ctx context.Context, tenantID, workspaceID, subject, bindingRef string) (SandboxDraftProposal, error)
}

// SandboxDraftBindingProvider converts the dedicated, immutable proposal into
// the V2 challenge spec. It cannot issue any grant itself.
type SandboxDraftBindingProvider struct {
	source SandboxDraftProposalSource
}

func NewSandboxDraftBindingProvider(source SandboxDraftProposalSource) (*SandboxDraftBindingProvider, error) {
	if source == nil {
		return nil, fmt.Errorf("%w: source is required", ErrSandboxDraftProposalInvalid)
	}
	return &SandboxDraftBindingProvider{source: source}, nil
}

func (p *SandboxDraftBindingProvider) LoadApprovalBinding(ctx context.Context, tenantID, workspaceID, bindingRef string) (ChallengeSpec, error) {
	spec, _, err := p.LoadApprovalBindingWithSourceSnapshot(ctx, tenantID, workspaceID, bindingRef)
	return spec, err
}

// LoadApprovalBindingWithSourceSnapshot derives the V2 spec and captures the
// proposal from the same authenticated source read for durable ceremony state.
func (p *SandboxDraftBindingProvider) LoadApprovalBindingWithSourceSnapshot(ctx context.Context, tenantID, workspaceID, bindingRef string) (ChallengeSpec, *SandboxDraftEvidenceSourceSnapshot, error) {
	if p == nil || p.source == nil {
		return ChallengeSpec{}, nil, fmt.Errorf("%w: source is required", ErrSandboxDraftProposalInvalid)
	}
	identity, ok := bindingControlIdentity(ctx)
	if !ok || identity.TenantID != tenantID || identity.WorkspaceID != workspaceID {
		return ChallengeSpec{}, nil, fmt.Errorf("%w: verified control identity is required", ErrSandboxDraftProposalInvalid)
	}
	proposal, err := p.source.LoadSandboxDraftProposal(ctx, tenantID, workspaceID, identity.Subject, bindingRef)
	if err != nil {
		return ChallengeSpec{}, nil, fmt.Errorf("%w: load source proposal: %v", ErrSandboxDraftProposalInvalid, err)
	}
	proposal = snapshotSandboxDraftProposal(proposal)
	if proposal.TenantID != tenantID || proposal.WorkspaceID != workspaceID || proposal.Subject != identity.Subject || proposal.BindingRef != bindingRef {
		return ChallengeSpec{}, nil, fmt.Errorf("%w: source proposal scope, subject, or reference mismatch", ErrSandboxDraftProposalInvalid)
	}
	spec, err := proposal.challengeSpec()
	if err != nil {
		return ChallengeSpec{}, nil, err
	}
	return spec, &SandboxDraftEvidenceSourceSnapshot{ControlIdentity: identity, Proposal: proposal}, nil
}

func snapshotSandboxDraftProposal(proposal SandboxDraftProposal) SandboxDraftProposal {
	proposal.PlanCanonicalJSON = append([]byte(nil), proposal.PlanCanonicalJSON...)
	proposal.IntentCanonicalJSON = append([]byte(nil), proposal.IntentCanonicalJSON...)
	proposal.EffectCanonicalJSON = append([]byte(nil), proposal.EffectCanonicalJSON...)
	return proposal
}

func validateSandboxDraftSourceSnapshot(spec ChallengeSpec, source *SandboxDraftEvidenceSourceSnapshot) error {
	if source == nil {
		return nil
	}
	for field, value := range map[string]string{
		"sandbox_draft_source subject":   source.ControlIdentity.Subject,
		"sandbox_draft_source tenant":    source.ControlIdentity.TenantID,
		"sandbox_draft_source workspace": source.ControlIdentity.WorkspaceID,
	} {
		if !validToken(value) {
			return invalidRecord(field + " is invalid")
		}
	}
	if source.ControlIdentity.TenantID != spec.TenantID || source.ControlIdentity.WorkspaceID != spec.WorkspaceID ||
		source.Proposal.TenantID != source.ControlIdentity.TenantID || source.Proposal.WorkspaceID != source.ControlIdentity.WorkspaceID ||
		source.Proposal.Subject != source.ControlIdentity.Subject {
		return invalidRecord("sandbox_draft_source identity or scope mismatch")
	}
	derived, err := source.Proposal.challengeSpec()
	if err != nil {
		return invalidRecord("sandbox_draft_source proposal is invalid")
	}
	if derived != spec {
		return invalidRecord("sandbox_draft_source does not match challenge_spec")
	}
	return nil
}

// Validate checks the immutable proposal shape and canonical source bytes. It
// does not authorize the proposal or construct a grant.
func (p SandboxDraftProposal) Validate() error {
	_, err := p.challengeSpec()
	return err
}

func (p SandboxDraftProposal) challengeSpec() (ChallengeSpec, error) {
	if p.SchemaVersion != SandboxDraftProposalSchemaV1 || p.ContractVersion != SandboxDraftProposalContractV1 {
		return ChallengeSpec{}, sandboxDraftProposalInvalid("unsupported schema or contract version")
	}
	for field, value := range map[string]string{
		"binding_ref":  p.BindingRef,
		"proposal_id":  p.ProposalID,
		"tenant_id":    p.TenantID,
		"workspace_id": p.WorkspaceID,
		"subject":      p.Subject,
		"template_id":  p.TemplateID,
	} {
		if !validToken(value) {
			return ChallengeSpec{}, sandboxDraftProposalInvalid(field + " is required and must not contain whitespace")
		}
	}
	if p.BindingRef != "sandbox-draft:"+p.ProposalID {
		return ChallengeSpec{}, sandboxDraftProposalInvalid("binding_ref must be sandbox-draft:<proposal_id>")
	}
	if !validSHA256(p.TemplateDigest) {
		return ChallengeSpec{}, sandboxDraftProposalInvalid("template_digest must be a lowercase sha256 reference")
	}
	planHash, err := canonicalSandboxDraftHash("plan", p.PlanCanonicalJSON, p.PlanHash)
	if err != nil {
		return ChallengeSpec{}, err
	}
	if err := validateSandboxDraftPlan(p.PlanCanonicalJSON, p.ProposalID, p.TemplateID, p.TemplateDigest); err != nil {
		return ChallengeSpec{}, err
	}
	if err := validateSandboxDraftIntent(p.IntentCanonicalJSON, p.ProposalID); err != nil {
		return ChallengeSpec{}, err
	}
	if err := validateSandboxDraftEffect(p.EffectCanonicalJSON); err != nil {
		return ChallengeSpec{}, err
	}
	intentHash, err := canonicalSandboxDraftHash("intent", p.IntentCanonicalJSON, p.IntentHash)
	if err != nil {
		return ChallengeSpec{}, err
	}
	effectHash, err := canonicalSandboxDraftHash("effect", p.EffectCanonicalJSON, p.EffectHash)
	if err != nil {
		return ChallengeSpec{}, err
	}

	spec := ChallengeSpec{
		BindingRef:                 p.BindingRef,
		ApprovalGrantSchemaVersion: contracts.ApprovalGrantSchemaV2,
		TenantID:                   p.TenantID,
		WorkspaceID:                p.WorkspaceID,
		Audience:                   contracts.ApprovalGrantAudiencePolicyDraftSandboxExecutorV1,
		PackID:                     contracts.ApprovalGrantPackIDPolicyDraftSandbox,
		PackVersion:                p.PackVersion,
		PackManifestHash:           p.PackManifestHash,
		Action:                     contracts.ApprovalGrantActionPolicyDraftSandbox,
		IntentHash:                 intentHash,
		EffectHash:                 effectHash,
		PlanHash:                   planHash,
		Decision:                   contracts.ApprovalGrantDecisionAllow,
		PolicyVersion:              p.PolicyVersion,
		PolicyEpoch:                p.PolicyEpoch,
		PolicyHash:                 p.PolicyHash,
		AuthoritySource:            p.AuthoritySource,
		AuthorityVersion:           p.AuthorityVersion,
		AuthoritySnapshotHash:      p.AuthoritySnapshotHash,
		RequiredRole:               p.RequiredRole,
		Quorum:                     p.Quorum,
		ServerIdentity:             p.ServerIdentity,
	}
	if err := spec.Validate(); err != nil {
		return ChallengeSpec{}, fmt.Errorf("%w: %v", ErrSandboxDraftProposalInvalid, err)
	}
	return spec, nil
}

func canonicalSandboxDraftHash(field string, raw []byte, expectedHash string) (string, error) {
	if !validSHA256(expectedHash) {
		return "", sandboxDraftProposalInvalid(field + " hash must be a lowercase sha256 reference")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", sandboxDraftProposalInvalid(field + " bytes must contain one JSON object")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", sandboxDraftProposalInvalid(field + " bytes must contain one JSON object")
	}
	if _, ok := value.(map[string]any); !ok {
		return "", sandboxDraftProposalInvalid(field + " bytes must contain a JSON object")
	}
	canonical, err := canonicalize.JCS(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return "", sandboxDraftProposalInvalid(field + " bytes must be RFC 8785 canonical JSON")
	}
	actualHash := canonicalize.ComputeArtifactHash(canonical)
	if actualHash != expectedHash {
		return "", sandboxDraftProposalInvalid(field + " hash does not match canonical bytes")
	}
	return actualHash, nil
}

type sandboxDraftPlan struct {
	ProposalID     string             `json:"proposal_id"`
	TemplateID     string             `json:"template_id"`
	TemplateDigest string             `json:"template_digest"`
	DefaultDeny    *bool              `json:"default_deny"`
	Egress         *[]json.RawMessage `json:"egress"`
	Mounts         *[]json.RawMessage `json:"mounts"`
	Secrets        *[]json.RawMessage `json:"secrets"`
}

func validateSandboxDraftPlan(raw []byte, proposalID, templateID, templateDigest string) error {
	var plan sandboxDraftPlan
	if err := decodeSandboxDraftObject(raw, &plan); err != nil {
		return sandboxDraftProposalInvalid("plan bytes must match the sandbox plan contract")
	}
	if plan.ProposalID != proposalID || plan.TemplateID != templateID || plan.TemplateDigest != templateDigest {
		return sandboxDraftProposalInvalid("plan must bind the proposal and template")
	}
	if plan.DefaultDeny == nil || !*plan.DefaultDeny {
		return sandboxDraftProposalInvalid("plan must use default_deny")
	}
	if plan.Egress == nil || len(*plan.Egress) != 0 || plan.Mounts == nil || len(*plan.Mounts) != 0 || plan.Secrets == nil || len(*plan.Secrets) != 0 {
		return sandboxDraftProposalInvalid("plan must not permit egress, mounts, or secrets")
	}
	return nil
}

type sandboxDraftIntent struct {
	ProposalID string `json:"proposal_id"`
}

func validateSandboxDraftIntent(raw []byte, proposalID string) error {
	var intent sandboxDraftIntent
	if err := json.Unmarshal(raw, &intent); err != nil || intent.ProposalID != proposalID {
		return sandboxDraftProposalInvalid("intent must bind the proposal")
	}
	return nil
}

type sandboxDraftEffect struct {
	EffectType string `json:"effect_type"`
	Scope      string `json:"scope"`
	Execution  string `json:"execution"`
}

func validateSandboxDraftEffect(raw []byte) error {
	var effect sandboxDraftEffect
	if err := decodeSandboxDraftObject(raw, &effect); err != nil || effect.EffectType != contracts.ApprovalGrantActionPolicyDraftSandbox || effect.Scope != "sandbox" || effect.Execution != "not_dispatched" {
		return sandboxDraftProposalInvalid("effect must be a non-dispatched policy.draft.sandbox")
	}
	return nil
}

func decodeSandboxDraftObject(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

type bindingControlIdentityContextKey struct{}

// withBindingControlIdentity is only used after Service has verified the
// authenticated control-plane identity. It is private so a provider cannot
// treat arbitrary request values as authority.
func withBindingControlIdentity(ctx context.Context, identity ControlIdentity) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, bindingControlIdentityContextKey{}, identity)
}

func bindingControlIdentity(ctx context.Context) (ControlIdentity, bool) {
	if ctx == nil {
		return ControlIdentity{}, false
	}
	identity, ok := ctx.Value(bindingControlIdentityContextKey{}).(ControlIdentity)
	if !ok || !validToken(identity.Subject) || !validToken(identity.TenantID) || !validToken(identity.WorkspaceID) {
		return ControlIdentity{}, false
	}
	return identity, true
}

func sandboxDraftProposalInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrSandboxDraftProposalInvalid, message)
}
