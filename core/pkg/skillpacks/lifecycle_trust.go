package skillpacks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ProjectionTrustRequest is the exact, immutable material a configured
// verifier must authenticate. The verifier is responsible for resolving the
// policy and certification references against current trusted evidence and
// validating their signatures before returning an allow decision.
type ProjectionTrustRequest struct {
	SchemaVersion  string                          `json:"schema_version"`
	Effect         contracts.SkillProjectionEffect `json:"effect"`
	Manifest       Manifest                        `json:"manifest"`
	ManifestBytes  []byte                          `json:"manifest_bytes"`
	ContentBytes   []byte                          `json:"content_bytes"`
	EvaluationTime time.Time                       `json:"evaluation_time"`
}

// ProjectionTrustDecision is the schema-pinned, canonical verifier output.
// VerificationRef names the verifier's immutable signed evidence record;
// DecisionHash protects the exact decision returned across the interface.
type ProjectionTrustDecision struct {
	SchemaVersion string `json:"schema_version"`
	Verdict       string `json:"verdict"`

	Action       string `json:"action"`
	TenantID     string `json:"tenant_id"`
	WorkspaceID  string `json:"workspace_id"`
	SkillID      string `json:"skill_id"`
	SkillVersion string `json:"skill_version"`
	AgentTarget  string `json:"agent_target"`

	CanonicalRequestHash string `json:"canonical_request_hash"`
	ArtifactHash         string `json:"artifact_hash"`
	ContentHash          string `json:"content_hash"`
	ManifestHash         string `json:"manifest_hash"`
	PolicyHash           string `json:"policy_hash"`
	SchemaHash           string `json:"schema_hash"`
	SandboxProfile       string `json:"sandbox_profile"`

	Publisher         string   `json:"publisher"`
	ManifestStatus    string   `json:"manifest_status"`
	PolicyRef         string   `json:"policy_ref"`
	CertificationRefs []string `json:"certification_refs"`

	VerifiedAt      time.Time `json:"verified_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	VerificationRef string    `json:"verification_ref"`
	VerifierID      string    `json:"verifier_id"`
	KeyID           string    `json:"key_id"`
	BindingHash     string    `json:"binding_hash"`
	Signature       string    `json:"signature,omitempty"`
	DecisionHash    string    `json:"decision_hash,omitempty"`
}

// ProjectionTrustVerifierKey pins the only verifier identity/key accepted by
// one lifecycle instance. HMACKey comes from server configuration, never from
// a projection request or SkillPack artifact.
type ProjectionTrustVerifierKey struct {
	VerifierID string
	KeyID      string
	HMACKey    []byte
}

// ProjectionTrustVerifierKeyring pins the current signing key plus the exact
// historical keys that may continue verifying durable receipts after a key
// rotation. Omitting a historical key revokes it; historical keys never sign
// new decisions or lifecycle state.
type ProjectionTrustVerifierKeyring struct {
	Current    ProjectionTrustVerifierKey
	Historical []ProjectionTrustVerifierKey
}

// ProjectionTrustVerifier is mandatory for every lifecycle instance. A
// concrete verifier may live in the runner. Install, readback, and rollback
// require a current exact-hash decision; revoke authenticates removal from the
// consumed revoke authority and the stored admission receipt instead.
type ProjectionTrustVerifier interface {
	VerifyProjectionTrust(ProjectionTrustRequest) (ProjectionTrustDecision, error)
}

// ProjectionTrustContextVerifier is an optional cancellation contract for
// verifiers that can stop their work when the lifecycle deadline elapses.
// Implementations must also satisfy ProjectionTrustVerifier for constructor
// compatibility; legacy verifiers are isolated behind the same hard deadline.
type ProjectionTrustContextVerifier interface {
	ProjectionTrustVerifier
	VerifyProjectionTrustContext(context.Context, ProjectionTrustRequest) (ProjectionTrustDecision, error)
}

type projectionTrustKeyIdentity struct {
	VerifierID string
	KeyID      string
}

type projectionTrustVerificationResult struct {
	decision ProjectionTrustDecision
	err      error
}

func (l *ProjectionLifecycle) validateProjectionAuthority(
	effect contracts.SkillProjectionEffect,
	consumedPermitRef string,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
	now time.Time,
) error {
	if err := l.validateProjectionAuthorityBinding(effect, consumedPermitRef, rollbackPermit); err != nil {
		return err
	}
	if err := effect.ValidateAt(now); err != nil {
		return err
	}
	if effect.Action == contracts.SkillProjectionActionRollback {
		return effect.ValidateRollbackPermit(*rollbackPermit, now)
	}
	return nil
}

func (l *ProjectionLifecycle) validateProjectionAuthorityBinding(
	effect contracts.SkillProjectionEffect,
	consumedPermitRef string,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
) error {
	if err := effect.Validate(); err != nil {
		return err
	}
	if effect.CanonicalRequestHash == "" {
		return fmt.Errorf("%w: canonical_request_hash is required", contracts.ErrSkillProjectionEffectIntegrity)
	}
	sealed, err := effect.Seal()
	if err != nil || !constantStringEqual(sealed.CanonicalRequestHash, effect.CanonicalRequestHash) {
		return fmt.Errorf("%w: canonical_request_hash mismatch", contracts.ErrSkillProjectionEffectIntegrity)
	}
	if !constantStringEqual(effect.ConsumedPermitRef, consumedPermitRef) {
		return fmt.Errorf("skillpacks: consumed permit reference mismatch")
	}
	if effect.Action == contracts.SkillProjectionActionRollback {
		if rollbackPermit == nil {
			return fmt.Errorf("skillpacks: rollback permit is required")
		}
		// IssuedAt is the one time guaranteed active by a structurally valid
		// permit. This checks its seal and exact effect binding without allowing
		// an expired permit to bypass recovery of its own pending journal.
		if err := effect.ValidateRollbackPermit(*rollbackPermit, rollbackPermit.IssuedAt); err != nil {
			return err
		}
		return l.verifyProjectionRollbackPermitAuthentication(*rollbackPermit)
	}
	if rollbackPermit != nil {
		return fmt.Errorf("skillpacks: rollback permit is only valid for rollback")
	}
	return nil
}

func validateProjectionArtifact(
	effect contracts.SkillProjectionEffect,
	artifact *SkillProjectionArtifact,
) (projectionGeneration, []byte, []byte, error) {
	if artifact == nil || len(artifact.Files) != 2 {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: V1 artifact requires exactly skillpack.json and SKILL.md")
	}
	manifestBytes, manifestOK := artifact.Files["skillpack.json"]
	contentBytes, contentOK := artifact.Files["SKILL.md"]
	if !manifestOK || !contentOK || len(manifestBytes) == 0 || len(contentBytes) == 0 {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: V1 artifact requires non-empty skillpack.json and SKILL.md")
	}
	if len(manifestBytes) > maxProjectionArtifactBytes || len(contentBytes) > maxProjectionArtifactBytes ||
		!utf8.Valid(manifestBytes) || !utf8.Valid(contentBytes) ||
		strings.ContainsRune(string(manifestBytes), 0) || strings.ContainsRune(string(contentBytes), 0) {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: artifact contains unsupported binary or oversized content")
	}
	if HashBytes(manifestBytes) != effect.ManifestHash || HashBytes(contentBytes) != effect.ContentHash {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: artifact byte hash mismatch")
	}
	artifactHash, err := contracts.ComputeSkillProjectionArtifactHash(effect.ManifestHash, effect.ContentHash)
	if err != nil || artifactHash != effect.ArtifactHash {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: artifact aggregate hash mismatch")
	}
	var manifest Manifest
	if err := decodeStrictProjectionJSON(manifestBytes, &manifest); err != nil {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: parse skillpack.json: %w", err)
	}
	if err := ValidateManifest(manifest, contentBytes); err != nil {
		return projectionGeneration{}, nil, nil, err
	}
	if manifest.Status == StatusBlocked {
		return projectionGeneration{}, nil, nil, fmt.Errorf("%w: blocked SkillPack cannot be projected", ErrProjectionTrustRejected)
	}
	if manifest.ID != effect.SkillID || manifest.Version != effect.SkillVersion || manifest.ContentHash != effect.ContentHash {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: manifest identity/hash does not match effect")
	}
	if len(manifest.Scripts) != 0 || len(manifest.Hooks) != 0 ||
		len(manifest.RequestedMCPServers) != 0 || len(manifest.RequestedMCPTools) != 0 {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: V1 projection denies scripts, hooks, MCP, and executable adapters")
	}
	if !containsString(manifest.AgentTargets, effect.AgentTarget) {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: manifest does not certify requested agent target")
	}
	if manifest.SignatureRef == "" || manifest.ProvenanceRef == "" ||
		!containsString(effect.CertificationRefs, manifest.SignatureRef) ||
		!containsString(effect.CertificationRefs, manifest.ProvenanceRef) {
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: certification refs do not bind manifest signature/provenance")
	}
	pack := SkillPack{Manifest: manifest, SkillMD: string(contentBytes)}
	if manifest.Status == StatusVerified {
		// The verifier's decision carries manifest_status onward, so "verified"
		// must not be the pack's own word. The V1 artifact is exactly these two
		// files, which makes it comparable with the first-party manifest.
		files := packTree{files: []packFile{{path: "SKILL.md", data: contentBytes}, {path: "skillpack.json", data: manifestBytes}}}
		if publisher := checkPublisher(pack, &files, loadKernelFirstPartyTrust()); publisher.State != PublisherFirstParty {
			return projectionGeneration{}, nil, nil, fmt.Errorf("%w: SkillPack declares status verified: %s", ErrProjectionTrustRejected, publisher.Reason)
		}
	}
	// Trust in every other pack is the configured verifier's decision
	// (verifyProjectionTrust), so this scan applies the prompt rules only.
	scan, err := scanPack(pack, nil)
	if err != nil || scan.Verdict != VerdictAllow {
		if err != nil {
			return projectionGeneration{}, nil, nil, err
		}
		return projectionGeneration{}, nil, nil, fmt.Errorf("skillpacks: prompt scan denied projection: %s", scan.ReasonCode)
	}
	return projectionGeneration{
		Generation:        effect.Generation,
		SkillVersion:      effect.SkillVersion,
		ArtifactHash:      effect.ArtifactHash,
		ContentHash:       effect.ContentHash,
		ManifestHash:      effect.ManifestHash,
		PolicyHash:        effect.PolicyHash,
		SchemaHash:        effect.SchemaHash,
		CertificationRefs: append([]string(nil), effect.CertificationRefs...),
		SandboxProfile:    effect.SandboxProfile,
	}, append([]byte(nil), manifestBytes...), append([]byte(nil), contentBytes...), nil
}

func (l *ProjectionLifecycle) verifyProjectionTrust(
	effect contracts.SkillProjectionEffect,
	record projectionGeneration,
	manifestBytes, contentBytes []byte,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
) (ProjectionTrustDecision, error) {
	if l == nil || l.verifier == nil {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: configured verifier is required", ErrProjectionTrustRejected)
	}
	if !projectionEffectMatchesGeneration(effect, record) ||
		HashBytes(manifestBytes) != effect.ManifestHash || HashBytes(contentBytes) != effect.ContentHash {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: verifier input does not match effect", ErrProjectionTrustRejected)
	}
	artifactHash, err := contracts.ComputeSkillProjectionArtifactHash(HashBytes(manifestBytes), HashBytes(contentBytes))
	if err != nil || !constantStringEqual(artifactHash, effect.ArtifactHash) {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: verifier artifact binding mismatch", ErrProjectionTrustRejected)
	}
	var manifest Manifest
	if err := decodeStrictProjectionJSON(manifestBytes, &manifest); err != nil {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: decode verifier manifest: %v", ErrProjectionTrustRejected, err)
	}
	if err := ValidateManifest(manifest, contentBytes); err != nil {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: verifier manifest validation: %v", ErrProjectionTrustRejected, err)
	}
	if manifest.Status == StatusBlocked {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: blocked SkillPack cannot be projected", ErrProjectionTrustRejected)
	}
	if manifest.ID != effect.SkillID || manifest.Version != effect.SkillVersion ||
		manifest.ContentHash != effect.ContentHash || strings.TrimSpace(manifest.PolicyRef) == "" ||
		!containsString(manifest.AgentTargets, effect.AgentTarget) ||
		manifest.SignatureRef == "" || manifest.ProvenanceRef == "" ||
		!containsString(effect.CertificationRefs, manifest.SignatureRef) ||
		!containsString(effect.CertificationRefs, manifest.ProvenanceRef) {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: manifest trust binding mismatch", ErrProjectionTrustRejected)
	}
	evaluationTime := l.clock().UTC()
	if err := l.validateProjectionAuthority(effect, effect.ConsumedPermitRef, rollbackPermit, evaluationTime); err != nil {
		return ProjectionTrustDecision{}, err
	}

	request := ProjectionTrustRequest{
		SchemaVersion:  ProjectionTrustRequestSchemaV1,
		Effect:         cloneProjectionEffect(effect),
		Manifest:       cloneProjectionManifest(manifest),
		ManifestBytes:  append([]byte(nil), manifestBytes...),
		ContentBytes:   append([]byte(nil), contentBytes...),
		EvaluationTime: evaluationTime,
	}
	decision, err := l.callProjectionTrustVerifier(request, effect, rollbackPermit)
	if err != nil {
		return ProjectionTrustDecision{}, errors.Join(ErrProjectionTrustRejected, err)
	}
	validationTime := l.clock().UTC()
	if err := l.validateProjectionAuthority(effect, effect.ConsumedPermitRef, rollbackPermit, validationTime); err != nil {
		return ProjectionTrustDecision{}, err
	}
	if err := l.validateProjectionTrustDecision(decision, effect, manifest, validationTime); err != nil {
		return ProjectionTrustDecision{}, err
	}
	return decision, nil
}

func (l *ProjectionLifecycle) callProjectionTrustVerifier(
	request ProjectionTrustRequest,
	effect contracts.SkillProjectionEffect,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
) (ProjectionTrustDecision, error) {
	if l.verifier == nil || l.verifierContext == nil || l.verifierInFlight == nil || l.verifierTimeout <= 0 {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: configured verifier is unavailable", ErrProjectionTrustRejected)
	}
	timeout := l.verifierTimeout
	if remaining := effect.ExpiresAt.Sub(request.EvaluationTime); remaining < timeout {
		timeout = remaining
	}
	if rollbackPermit != nil {
		if remaining := rollbackPermit.ExpiresAt.Sub(request.EvaluationTime); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: verifier authority deadline elapsed", ErrProjectionTrustRejected)
	}
	ctx, cancel := context.WithTimeout(l.verifierContext, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return ProjectionTrustDecision{}, errors.Join(ErrProjectionTrustRejected, err)
	}
	select {
	case l.verifierInFlight <- struct{}{}:
	default:
		return ProjectionTrustDecision{}, fmt.Errorf("%w: verifier call is already in flight", ErrProjectionTrustRejected)
	}

	verifier := l.verifier
	gate := l.verifierInFlight
	results := make(chan projectionTrustVerificationResult, 1)
	go func() {
		var decision ProjectionTrustDecision
		var err error
		if contextual, ok := verifier.(ProjectionTrustContextVerifier); ok {
			decision, err = contextual.VerifyProjectionTrustContext(ctx, request)
		} else {
			decision, err = verifier.VerifyProjectionTrust(request)
		}
		<-gate
		results <- projectionTrustVerificationResult{decision: decision, err: err}
	}()

	select {
	case result := <-results:
		return result.decision, result.err
	case <-ctx.Done():
		return ProjectionTrustDecision{}, errors.Join(ErrProjectionTrustRejected, ctx.Err())
	}
}

func (l *ProjectionLifecycle) validateProjectionPublicationAuthority(
	effect contracts.SkillProjectionEffect,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
	decision ProjectionTrustDecision,
	revocationState *projectionLifecycleState,
) error {
	now := l.clock().UTC()
	if err := l.validateProjectionAuthority(effect, effect.ConsumedPermitRef, rollbackPermit, now); err != nil {
		return err
	}
	if effect.Action == contracts.SkillProjectionActionRevoke {
		if revocationState == nil {
			return fmt.Errorf("%w: authenticated revocation state is required", ErrProjectionTrustRejected)
		}
		_, err := l.validateStoredRevocationArchive(effect, *revocationState)
		return err
	}
	if err := verifyProjectionTrustDecisionIntegrity(decision); err != nil {
		return err
	}
	if err := verifyProjectionTrustDecisionSignature(decision, l.verifierKey); err != nil {
		return err
	}
	expectedBindingHash, err := projectionTrustBindingHash(projectionTrustBindingFromEffect(effect))
	if err != nil || !constantStringEqual(expectedBindingHash, decision.BindingHash) ||
		decision.VerifiedAt.After(now) || !now.Before(decision.ExpiresAt) {
		return fmt.Errorf("%w: trust decision is not current for publication", ErrProjectionTrustRejected)
	}
	return nil
}

func (l *ProjectionLifecycle) validateProjectionTrustDecision(
	decision ProjectionTrustDecision,
	effect contracts.SkillProjectionEffect,
	manifest Manifest,
	now time.Time,
) error {
	if err := verifyProjectionTrustDecisionIntegrity(decision); err != nil {
		return err
	}
	if err := verifyProjectionTrustDecisionSignature(decision, l.verifierKey); err != nil {
		return err
	}
	expectedBindingHash, err := projectionTrustBindingHash(projectionTrustBindingFromEffect(effect))
	if err != nil {
		return fmt.Errorf("%w: compute trust decision binding: %v", ErrProjectionTrustRejected, err)
	}
	if decision.SchemaVersion != ProjectionTrustDecisionSchemaV1 || decision.Verdict != VerdictAllow ||
		decision.Action != effect.Action || decision.TenantID != effect.TenantID ||
		decision.WorkspaceID != effect.WorkspaceID || decision.SkillID != effect.SkillID ||
		decision.SkillVersion != effect.SkillVersion || decision.AgentTarget != effect.AgentTarget ||
		decision.CanonicalRequestHash != effect.CanonicalRequestHash ||
		decision.ArtifactHash != effect.ArtifactHash || decision.ContentHash != effect.ContentHash ||
		decision.ManifestHash != effect.ManifestHash || decision.PolicyHash != effect.PolicyHash ||
		decision.SchemaHash != effect.SchemaHash || decision.SandboxProfile != effect.SandboxProfile ||
		decision.BindingHash != expectedBindingHash || decision.Publisher != manifest.Publisher ||
		decision.ManifestStatus != manifest.Status || decision.PolicyRef != manifest.PolicyRef ||
		!equalStrings(decision.CertificationRefs, effect.CertificationRefs) {
		return fmt.Errorf("%w: trust decision does not exactly bind the request", ErrProjectionTrustRejected)
	}
	if !validProjectionSHA256(decision.VerificationRef) || decision.VerifiedAt.IsZero() ||
		decision.ExpiresAt.IsZero() || decision.VerifiedAt.Location() != time.UTC ||
		decision.ExpiresAt.Location() != time.UTC || decision.VerifiedAt.After(now) ||
		!now.Before(decision.ExpiresAt) || !decision.ExpiresAt.After(decision.VerifiedAt) {
		return fmt.Errorf("%w: trust decision is not current", ErrProjectionTrustRejected)
	}
	return nil
}

func cloneProjectionEffect(effect contracts.SkillProjectionEffect) contracts.SkillProjectionEffect {
	clone := effect
	clone.CertificationRefs = append([]string(nil), effect.CertificationRefs...)
	return clone
}

func cloneProjectionManifest(manifest Manifest) Manifest {
	clone := manifest
	clone.AgentTargets = append([]string(nil), manifest.AgentTargets...)
	clone.RequestedMCPServers = append([]string(nil), manifest.RequestedMCPServers...)
	clone.RequestedMCPTools = append([]string(nil), manifest.RequestedMCPTools...)
	clone.Hooks = append([]string(nil), manifest.Hooks...)
	clone.Scripts = append([]string(nil), manifest.Scripts...)
	return clone
}

type projectionTrustBinding struct {
	SchemaVersion         string `json:"schema_version"`
	Action                string `json:"action"`
	TenantID              string `json:"tenant_id"`
	WorkspaceID           string `json:"workspace_id"`
	SkillID               string `json:"skill_id"`
	SkillVersion          string `json:"skill_version"`
	AgentTarget           string `json:"agent_target"`
	CanonicalRequestHash  string `json:"canonical_request_hash"`
	ArtifactHash          string `json:"artifact_hash"`
	ContentHash           string `json:"content_hash"`
	ManifestHash          string `json:"manifest_hash"`
	PolicyHash            string `json:"policy_hash"`
	SchemaHash            string `json:"schema_hash"`
	CertificationRefsHash string `json:"certification_refs_hash"`
	SandboxProfile        string `json:"sandbox_profile"`
}

func projectionCertificationRefsHash(refs []string) string {
	data, err := json.Marshal(refs)
	if err != nil {
		return ""
	}
	return HashBytes(append([]byte("helm.skill-projection-certification-refs.v1\x00"), data...))
}

func projectionTrustBindingHash(binding projectionTrustBinding) (string, error) {
	data, err := json.Marshal(binding)
	if err != nil {
		return "", fmt.Errorf("skillpacks: seal projection trust binding: %w", err)
	}
	return HashBytes(data), nil
}

func projectionTrustBindingFromEffect(effect contracts.SkillProjectionEffect) projectionTrustBinding {
	return projectionTrustBinding{
		SchemaVersion: projectionTrustBindingSchemaV1, Action: effect.Action,
		TenantID: effect.TenantID, WorkspaceID: effect.WorkspaceID,
		SkillID: effect.SkillID, SkillVersion: effect.SkillVersion, AgentTarget: effect.AgentTarget,
		CanonicalRequestHash: effect.CanonicalRequestHash,
		ArtifactHash:         effect.ArtifactHash, ContentHash: effect.ContentHash, ManifestHash: effect.ManifestHash,
		PolicyHash: effect.PolicyHash, SchemaHash: effect.SchemaHash,
		CertificationRefsHash: projectionCertificationRefsHash(effect.CertificationRefs),
		SandboxProfile:        effect.SandboxProfile,
	}
}

func projectionTrustBindingFromDecision(decision ProjectionTrustDecision) projectionTrustBinding {
	return projectionTrustBinding{
		SchemaVersion: projectionTrustBindingSchemaV1, Action: decision.Action,
		TenantID: decision.TenantID, WorkspaceID: decision.WorkspaceID,
		SkillID: decision.SkillID, SkillVersion: decision.SkillVersion, AgentTarget: decision.AgentTarget,
		CanonicalRequestHash: decision.CanonicalRequestHash,
		ArtifactHash:         decision.ArtifactHash, ContentHash: decision.ContentHash, ManifestHash: decision.ManifestHash,
		PolicyHash: decision.PolicyHash, SchemaHash: decision.SchemaHash,
		CertificationRefsHash: projectionCertificationRefsHash(decision.CertificationRefs),
		SandboxProfile:        decision.SandboxProfile,
	}
}

func projectionTrustBindingFromGeneration(
	state projectionLifecycleState,
	record projectionGeneration,
) projectionTrustBinding {
	return projectionTrustBinding{
		SchemaVersion: projectionTrustBindingSchemaV1, Action: record.TrustAction,
		TenantID: state.TenantID, WorkspaceID: state.WorkspaceID,
		SkillID: state.SkillID, SkillVersion: record.SkillVersion, AgentTarget: state.AgentTarget,
		CanonicalRequestHash: record.TrustCanonicalHash,
		ArtifactHash:         record.ArtifactHash, ContentHash: record.ContentHash, ManifestHash: record.ManifestHash,
		PolicyHash: record.PolicyHash, SchemaHash: record.SchemaHash,
		CertificationRefsHash: projectionCertificationRefsHash(record.CertificationRefs),
		SandboxProfile:        record.SandboxProfile,
	}
}

func projectionTrustBindingFromResult(result ProjectionLifecycleResult) projectionTrustBinding {
	return projectionTrustBinding{
		SchemaVersion: projectionTrustBindingSchemaV1, Action: result.TrustDecisionAction,
		TenantID: result.TenantID, WorkspaceID: result.WorkspaceID,
		SkillID: result.SkillID, SkillVersion: result.SkillVersion, AgentTarget: result.AgentTarget,
		CanonicalRequestHash:  result.TrustDecisionCanonical,
		ArtifactHash:          result.TrustArtifactHash,
		ContentHash:           result.TrustContentHash,
		ManifestHash:          result.TrustManifestHash,
		PolicyHash:            result.TrustPolicyHash,
		SchemaHash:            result.TrustSchemaHash,
		CertificationRefsHash: result.TrustCertificationHash,
		SandboxProfile:        result.TrustSandboxProfile,
	}
}

// SignProjectionTrustDecision creates the authenticated receipt returned by a
// configured verifier. Kernel independently recomputes both the decision hash
// and HMAC using its pinned verifier key.
func SignProjectionTrustDecision(
	decision ProjectionTrustDecision,
	key ProjectionTrustVerifierKey,
) (ProjectionTrustDecision, error) {
	if err := validateProjectionTrustVerifierKey(key); err != nil {
		return ProjectionTrustDecision{}, err
	}
	if !validProjectionSHA256(decision.CanonicalRequestHash) {
		return ProjectionTrustDecision{}, fmt.Errorf("%w: trust decision canonical request hash is invalid", ErrProjectionTrustRejected)
	}
	bindingHash, err := projectionTrustBindingHash(projectionTrustBindingFromDecision(decision))
	if err != nil {
		return ProjectionTrustDecision{}, err
	}
	decision.BindingHash = bindingHash
	decision.VerifierID = key.VerifierID
	decision.KeyID = key.KeyID
	sealed, err := SealProjectionTrustDecision(decision)
	if err != nil {
		return ProjectionTrustDecision{}, err
	}
	sealed.Signature = projectionTrustSignature(sealed.DecisionHash, sealed.BindingHash, key)
	return sealed, nil
}

// SignProjectionRollbackPermit authenticates a separately action-bound
// rollback permit with an explicitly configured authority key. Permit.Seal
// remains an integrity operation and cannot mint this authority signature.
func SignProjectionRollbackPermit(
	permit contracts.SkillProjectionRollbackPermit,
	key ProjectionTrustVerifierKey,
) (contracts.SkillProjectionRollbackPermit, error) {
	if err := validateProjectionTrustVerifierKey(key); err != nil {
		return contracts.SkillProjectionRollbackPermit{}, err
	}
	permit.IssuerID = key.VerifierID
	permit.KeyID = key.KeyID
	permit.Signature = ""
	sealed, err := permit.Seal()
	if err != nil {
		return contracts.SkillProjectionRollbackPermit{}, err
	}
	sealed.Signature = projectionRollbackPermitSignature(sealed.PermitHash, key)
	return sealed, nil
}

func validateProjectionTrustVerifierKey(key ProjectionTrustVerifierKey) error {
	if !validProjectionTrustIdentity(key.VerifierID) || !validProjectionTrustIdentity(key.KeyID) ||
		len(key.HMACKey) < 32 || len(key.HMACKey) > 4096 {
		return fmt.Errorf("%w: pinned verifier identity/key is invalid", ErrProjectionTrustRejected)
	}
	return nil
}

func validateProjectionTrustVerifierKeyring(keyring ProjectionTrustVerifierKeyring) error {
	keys := append([]ProjectionTrustVerifierKey{keyring.Current}, keyring.Historical...)
	seen := make(map[projectionTrustKeyIdentity]struct{}, len(keys))
	for _, key := range keys {
		if err := validateProjectionTrustVerifierKey(key); err != nil {
			return err
		}
		identity := projectionTrustKeyIdentity{VerifierID: key.VerifierID, KeyID: key.KeyID}
		if _, ok := seen[identity]; ok {
			return fmt.Errorf("%w: duplicate verifier identity/key", ErrProjectionTrustRejected)
		}
		seen[identity] = struct{}{}
	}
	return nil
}

func cloneProjectionTrustVerifierKey(key ProjectionTrustVerifierKey) ProjectionTrustVerifierKey {
	key.HMACKey = append([]byte(nil), key.HMACKey...)
	return key
}

func validProjectionTrustIdentity(value string) bool {
	return validProjectionTrustToken(value, 128)
}

func validProjectionTrustToken(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && strings.IndexFunc(value, func(r rune) bool {
		return r == 0 || r == '\u007f' || r == '\u2028' || r == '\u2029' ||
			r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) == -1
}

func validProjectionTrustSignature(value string) bool {
	if len(value) != len(projectionTrustSignaturePrefix)+64 || !strings.HasPrefix(value, projectionTrustSignaturePrefix) {
		return false
	}
	digest := strings.TrimPrefix(value, projectionTrustSignaturePrefix)
	if strings.ToLower(digest) != digest {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size
}

func projectionTrustSignature(decisionHash, bindingHash string, key ProjectionTrustVerifierKey) string {
	mac := hmac.New(sha256.New, key.HMACKey)
	_, _ = mac.Write([]byte(ProjectionTrustDecisionSchemaV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.VerifierID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.KeyID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(decisionHash))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(bindingHash))
	return projectionTrustSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

func projectionLifecycleStateSignature(stateHash string, key ProjectionTrustVerifierKey) string {
	mac := hmac.New(sha256.New, key.HMACKey)
	_, _ = mac.Write([]byte(projectionLifecycleStateMACV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.VerifierID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.KeyID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(stateHash))
	return projectionTrustSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

func projectionRecoveryJournalSignature(journalHash string, key ProjectionTrustVerifierKey) string {
	mac := hmac.New(sha256.New, key.HMACKey)
	_, _ = mac.Write([]byte(projectionRecoveryJournalMACV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.VerifierID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.KeyID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(journalHash))
	return projectionTrustSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

func projectionRollbackPermitSignature(permitHash string, key ProjectionTrustVerifierKey) string {
	mac := hmac.New(sha256.New, key.HMACKey)
	_, _ = mac.Write([]byte(projectionRollbackPermitMACV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(contracts.SkillProjectionRollbackPermitSchemaV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(contracts.SkillProjectionRollbackPermitContractV1))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.VerifierID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.KeyID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(permitHash))
	return projectionTrustSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

func (l *ProjectionLifecycle) verifyProjectionRollbackPermitAuthentication(
	permit contracts.SkillProjectionRollbackPermit,
) error {
	if !validProjectionTrustIdentity(permit.IssuerID) || !validProjectionTrustIdentity(permit.KeyID) ||
		!validProjectionTrustSignature(permit.Signature) {
		return fmt.Errorf("%w: authenticated rollback permit is required", contracts.ErrSkillProjectionEffectIntegrity)
	}
	key, ok := l.verificationKeys[projectionTrustKeyIdentity{VerifierID: permit.IssuerID, KeyID: permit.KeyID}]
	if !ok {
		return fmt.Errorf("%w: rollback permit issuer/key is not accepted", contracts.ErrSkillProjectionEffectIntegrity)
	}
	expected := projectionRollbackPermitSignature(permit.PermitHash, key)
	if !constantStringEqual(permit.Signature, expected) {
		return fmt.Errorf("%w: rollback permit signature mismatch", contracts.ErrSkillProjectionEffectIntegrity)
	}
	return nil
}

func (l *ProjectionLifecycle) verifyProjectionRollbackPermitCurrentAuthority(
	permit contracts.SkillProjectionRollbackPermit,
) error {
	if permit.IssuerID != l.verifierKey.VerifierID || permit.KeyID != l.verifierKey.KeyID {
		return fmt.Errorf("%w: fresh rollback permit must use current issuer/key", contracts.ErrSkillProjectionEffectIntegrity)
	}
	expected := projectionRollbackPermitSignature(permit.PermitHash, l.verifierKey)
	if !constantStringEqual(permit.Signature, expected) {
		return fmt.Errorf("%w: fresh rollback permit signature mismatch", contracts.ErrSkillProjectionEffectIntegrity)
	}
	return nil
}

func verifyProjectionTrustDecisionSignature(decision ProjectionTrustDecision, key ProjectionTrustVerifierKey) error {
	if err := validateProjectionTrustVerifierKey(key); err != nil {
		return err
	}
	if decision.VerifierID != key.VerifierID || decision.KeyID != key.KeyID ||
		!validProjectionSHA256(decision.BindingHash) || !validProjectionTrustSignature(decision.Signature) {
		return fmt.Errorf("%w: trust decision verifier identity/key mismatch", ErrProjectionTrustRejected)
	}
	expected := projectionTrustSignature(decision.DecisionHash, decision.BindingHash, key)
	if !constantStringEqual(decision.Signature, expected) {
		return fmt.Errorf("%w: trust decision signature mismatch", ErrProjectionTrustRejected)
	}
	return nil
}

func (l *ProjectionLifecycle) verifyStoredProjectionTrustSignature(
	decisionHash, bindingHash, verifierID, keyID, signature string,
) error {
	key, ok := l.verificationKeys[projectionTrustKeyIdentity{VerifierID: verifierID, KeyID: keyID}]
	if !ok {
		return fmt.Errorf("%w: stored trust verifier identity/key is not accepted", ErrProjectionTrustRejected)
	}
	decision := ProjectionTrustDecision{
		BindingHash:  bindingHash,
		DecisionHash: decisionHash,
		VerifierID:   verifierID,
		KeyID:        keyID,
		Signature:    signature,
	}
	return verifyProjectionTrustDecisionSignature(decision, key)
}

func projectionGenerationMatchesTrustEffect(
	state projectionLifecycleState,
	record projectionGeneration,
) bool {
	if record.TrustAction != contracts.SkillProjectionActionInstall && record.TrustAction != contracts.SkillProjectionActionRollback {
		return false
	}
	bindingHash, err := projectionTrustBindingHash(projectionTrustBindingFromGeneration(state, record))
	return err == nil && constantStringEqual(bindingHash, record.TrustBindingHash)
}

func projectionResultMatchesTrustEffect(result ProjectionLifecycleResult) bool {
	bindingHash, err := projectionTrustBindingHash(projectionTrustBindingFromResult(result))
	if err != nil || !constantStringEqual(bindingHash, result.TrustBindingHash) {
		return false
	}
	switch result.Action {
	case contracts.SkillProjectionActionInstall, contracts.SkillProjectionActionRollback:
		if result.TrustDecisionAction != result.Action || result.TrustDecisionCanonical != result.CanonicalRequestHash {
			return false
		}
		validStatus := result.Status == "installed" || result.Status == "upgraded"
		if result.Action == contracts.SkillProjectionActionRollback {
			validStatus = result.Status == "rolled_back"
		}
		return validStatus && result.NewArtifactHash == result.TrustArtifactHash && result.NewContentHash == result.TrustContentHash &&
			result.NewManifestHash == result.TrustManifestHash && result.ObservedArtifactHash == result.TrustArtifactHash &&
			result.ObservedContentHash == result.TrustContentHash && result.ObservedManifestHash == result.TrustManifestHash
	case contracts.SkillProjectionActionReadback:
		if result.TrustDecisionAction != result.Action || result.TrustDecisionCanonical != result.CanonicalRequestHash {
			return false
		}
		if result.PreviousArtifactHash != result.TrustArtifactHash || result.PreviousContentHash != result.TrustContentHash ||
			result.PreviousManifestHash != result.TrustManifestHash {
			return false
		}
		if result.Status == projectionStatusRevoked {
			return result.NewArtifactHash == "" && result.NewContentHash == "" && result.NewManifestHash == "" &&
				result.ObservedArtifactHash == "" && result.ObservedContentHash == "" && result.ObservedManifestHash == ""
		}
		return result.Status == projectionStatusActive && result.NewArtifactHash == result.TrustArtifactHash &&
			result.NewContentHash == result.TrustContentHash && result.NewManifestHash == result.TrustManifestHash &&
			result.ObservedArtifactHash == result.TrustArtifactHash && result.ObservedContentHash == result.TrustContentHash &&
			result.ObservedManifestHash == result.TrustManifestHash
	case contracts.SkillProjectionActionRevoke:
		if result.TrustDecisionAction != contracts.SkillProjectionActionInstall &&
			result.TrustDecisionAction != contracts.SkillProjectionActionRollback {
			return false
		}
		return result.Status == projectionStatusRevoked && result.PreviousArtifactHash == result.TrustArtifactHash &&
			result.PreviousContentHash == result.TrustContentHash && result.PreviousManifestHash == result.TrustManifestHash &&
			result.NewArtifactHash == "" && result.NewContentHash == "" && result.NewManifestHash == "" &&
			result.ObservedArtifactHash == "" && result.ObservedContentHash == "" && result.ObservedManifestHash == ""
	default:
		return false
	}
}

func (l *ProjectionLifecycle) verifyReplayTrust(
	effect contracts.SkillProjectionEffect,
	state projectionLifecycleState,
	rollbackPermit *contracts.SkillProjectionRollbackPermit,
) (ProjectionTrustDecision, error) {
	if effect.Action == contracts.SkillProjectionActionRevoke {
		replay, ok := findProjectionReplay(state.Replays, effect.IdempotencyKey)
		if !ok {
			return ProjectionTrustDecision{}, fmt.Errorf("%w: revoke replay trust receipt mismatch", ErrProjectionDrift)
		}
		if _, err := l.validateStoredRevocationReplay(effect, state, replay.Result); err != nil {
			return ProjectionTrustDecision{}, err
		}
		return ProjectionTrustDecision{}, nil
	}
	for _, record := range state.Generations {
		if !projectionEffectMatchesGeneration(effect, record) {
			continue
		}
		manifestBytes, contentBytes, err := l.readGeneration(effect, record)
		if err != nil {
			return ProjectionTrustDecision{}, err
		}
		return l.verifyProjectionTrust(effect, record, manifestBytes, contentBytes, rollbackPermit)
	}
	return ProjectionTrustDecision{}, fmt.Errorf("%w: replay has no retained trust material", ErrProjectionDrift)
}

func (l *ProjectionLifecycle) validateStoredRevocationState(
	effect contracts.SkillProjectionEffect,
	state projectionLifecycleState,
) error {
	if effect.Action != contracts.SkillProjectionActionRevoke ||
		state.TenantID != effect.TenantID || state.WorkspaceID != effect.WorkspaceID ||
		state.SkillID != effect.SkillID || state.AgentTarget != effect.AgentTarget {
		return fmt.Errorf("%w: revocation state identity mismatch", ErrProjectionDrift)
	}
	if err := l.verifyProjectionLifecycleState(state); err != nil {
		return err
	}
	return l.verifyProjectionStateTrustReceipts(state)
}

func (l *ProjectionLifecycle) validateStoredRevocationArchive(
	effect contracts.SkillProjectionEffect,
	state projectionLifecycleState,
) (projectionGeneration, error) {
	if err := l.validateStoredRevocationState(effect, state); err != nil {
		return projectionGeneration{}, err
	}
	record, ok := findProjectionGeneration(state.Generations, state.ArchiveGeneration)
	if !ok || !projectionEffectMatchesGeneration(effect, record) {
		return projectionGeneration{}, fmt.Errorf("%w: archived revocation trust receipt mismatch", ErrProjectionDrift)
	}
	return record, nil
}

func (l *ProjectionLifecycle) validateStoredRevocationReplay(
	effect contracts.SkillProjectionEffect,
	state projectionLifecycleState,
	result ProjectionLifecycleResult,
) (projectionGeneration, error) {
	if err := l.validateStoredRevocationState(effect, state); err != nil {
		return projectionGeneration{}, err
	}
	for _, record := range state.Generations {
		if projectionEffectMatchesGeneration(effect, record) && projectionResultMatchesGenerationTrust(result, record) {
			return record, nil
		}
	}
	return projectionGeneration{}, fmt.Errorf("%w: revoke replay has no retained trust receipt", ErrProjectionDrift)
}

func bindProjectionResultTrust(
	result *ProjectionLifecycleResult,
	decision ProjectionTrustDecision,
	effect contracts.SkillProjectionEffect,
) {
	result.TrustVerificationRef = decision.VerificationRef
	result.TrustDecisionHash = decision.DecisionHash
	result.TrustDecisionAction = decision.Action
	result.TrustDecisionCanonical = decision.CanonicalRequestHash
	result.TrustVerifierID = decision.VerifierID
	result.TrustKeyID = decision.KeyID
	result.TrustBindingHash = decision.BindingHash
	result.TrustDecisionSignature = decision.Signature
	result.TrustArtifactHash = effect.ArtifactHash
	result.TrustContentHash = effect.ContentHash
	result.TrustManifestHash = effect.ManifestHash
	result.TrustPolicyHash = effect.PolicyHash
	result.TrustSchemaHash = effect.SchemaHash
	result.TrustCertificationHash = projectionCertificationRefsHash(effect.CertificationRefs)
	result.TrustSandboxProfile = effect.SandboxProfile
}

func bindProjectionResultStoredGenerationTrust(
	result *ProjectionLifecycleResult,
	record projectionGeneration,
) {
	result.TrustVerificationRef = record.TrustVerificationRef
	result.TrustDecisionHash = record.TrustDecisionHash
	result.TrustDecisionAction = record.TrustAction
	result.TrustDecisionCanonical = record.TrustCanonicalHash
	result.TrustVerifierID = record.TrustVerifierID
	result.TrustKeyID = record.TrustKeyID
	result.TrustBindingHash = record.TrustBindingHash
	result.TrustDecisionSignature = record.TrustDecisionSignature
	result.TrustArtifactHash = record.ArtifactHash
	result.TrustContentHash = record.ContentHash
	result.TrustManifestHash = record.ManifestHash
	result.TrustPolicyHash = record.PolicyHash
	result.TrustSchemaHash = record.SchemaHash
	result.TrustCertificationHash = projectionCertificationRefsHash(record.CertificationRefs)
	result.TrustSandboxProfile = record.SandboxProfile
}

func projectionResultMatchesGenerationTrust(
	result ProjectionLifecycleResult,
	record projectionGeneration,
) bool {
	return result.TrustVerificationRef == record.TrustVerificationRef &&
		result.TrustDecisionHash == record.TrustDecisionHash && result.TrustDecisionAction == record.TrustAction &&
		result.TrustDecisionCanonical == record.TrustCanonicalHash && result.TrustVerifierID == record.TrustVerifierID &&
		result.TrustKeyID == record.TrustKeyID && result.TrustBindingHash == record.TrustBindingHash &&
		result.TrustDecisionSignature == record.TrustDecisionSignature && result.TrustArtifactHash == record.ArtifactHash &&
		result.TrustContentHash == record.ContentHash && result.TrustManifestHash == record.ManifestHash &&
		result.TrustPolicyHash == record.PolicyHash && result.TrustSchemaHash == record.SchemaHash &&
		result.TrustCertificationHash == projectionCertificationRefsHash(record.CertificationRefs) &&
		result.TrustSandboxProfile == record.SandboxProfile
}

func (l *ProjectionLifecycle) verifyProjectionStateTrustReceipts(state projectionLifecycleState) error {
	for _, retained := range state.Generations {
		if !projectionGenerationMatchesTrustEffect(state, retained) {
			return fmt.Errorf("%w: retained generation trust effect mismatch", ErrProjectionDrift)
		}
		if err := l.verifyStoredProjectionTrustSignature(
			retained.TrustDecisionHash, retained.TrustBindingHash, retained.TrustVerifierID,
			retained.TrustKeyID, retained.TrustDecisionSignature,
		); err != nil {
			return fmt.Errorf("%w: retained generation trust receipt: %v", ErrProjectionDrift, err)
		}
	}
	for _, replay := range state.Replays {
		if err := l.verifyStoredProjectionTrustSignature(
			replay.Result.TrustDecisionHash, replay.Result.TrustBindingHash, replay.Result.TrustVerifierID,
			replay.Result.TrustKeyID, replay.Result.TrustDecisionSignature,
		); err != nil {
			return fmt.Errorf("%w: replay trust receipt: %v", ErrProjectionDrift, err)
		}
	}
	return nil
}

func validProjectionSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	digest := strings.TrimPrefix(value, "sha256:")
	if strings.ToLower(digest) != digest {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == 32
}

func validProjectionAction(action string) bool {
	switch action {
	case contracts.SkillProjectionActionInstall, contracts.SkillProjectionActionReadback,
		contracts.SkillProjectionActionRevoke, contracts.SkillProjectionActionRollback:
		return true
	default:
		return false
	}
}

func constantStringEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func constantBytesEqual(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
