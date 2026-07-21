package approvalceremony

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
)

const (
	SandboxDraftEvidenceMetadataDomainV1 = "HELM/SandboxDraftEvidenceMetadata/v1"
	SandboxDraftEvidenceMetadataSchemaV1 = "sandbox-draft-evidence-metadata.v1"
	SandboxDraftReceiptDomainV1          = "HELM/SandboxDraftReceipt/v1"
	SandboxDraftReceiptSchemaV1          = "sandbox-draft-receipt.v1"
	SandboxDraftEvidenceTemplateID       = "draft_policy"
	SandboxDraftEvidenceArtifactTypeV1   = "sandbox_policy_draft.v1"

	sandboxDraftArtifactPath             = "artifacts/sandbox_policy_draft.v1.md"
	sandboxDraftConsumptionPath          = "consumption/approval-grant-consumption.v2.json"
	sandboxDraftConsumptionSignaturePath = "consumption/approval-grant-consumption.v2.signature.json"
	sandboxDraftBindingPath              = "policy/sandbox-draft-binding.json"
	sandboxDraftReceiptPath              = "receipts/sandbox-draft-receipt.json"
)

var ErrSandboxDraftEvidenceRejected = errors.New("sandbox draft evidence rejected")

// SandboxDraftEvidenceProfile is the fixed no-egress/no-mount/no-secret
// profile serialized by the data-plane sandbox draft archive.
type SandboxDraftEvidenceProfile struct {
	TemplateID        string `json:"template_id"`
	TemplateDigest    string `json:"template_digest"`
	DefaultDenyEgress bool   `json:"default_deny_egress"`
	NoMounts          bool   `json:"no_mounts"`
	NoSecrets         bool   `json:"no_secrets"`
}

// SandboxDraftEvidenceArtifact is the one reviewable draft output. Its body is
// raw UTF-8 markdown, so its exact bytes—not a JSON reserialization—are bound.
type SandboxDraftEvidenceArtifact struct {
	ArtifactType         string `json:"artifact_type"`
	ContentHash          string `json:"content_hash"`
	RedactedBodyMarkdown string `json:"body_markdown"`
}

// SandboxDraftEvidenceReceipt is the inner receipt serialized in the archive.
// It is not an outer EvidencePack receipt and carries no receipt authority.
type SandboxDraftEvidenceReceipt struct {
	Domain              string `json:"domain"`
	SchemaVersion       string `json:"schema_version"`
	TenantID            string `json:"tenant_id"`
	WorkspaceID         string `json:"workspace_id"`
	ConsumerSubject     string `json:"consumer_subject"`
	IdempotencyKey      string `json:"idempotency_key"`
	ProposalID          string `json:"proposal_id"`
	ProposalContentHash string `json:"proposal_content_hash"`
	ConsumptionHash     string `json:"consumption_hash"`
	TemplateID          string `json:"template_id"`
	TemplateDigest      string `json:"template_digest"`
	InputHash           string `json:"input_hash"`
	ArtifactType        string `json:"artifact_type"`
	ArtifactContentHash string `json:"artifact_content_hash"`
}

// SandboxDraftEvidenceMetadata is the data-plane metadata profile. It binds
// the archive's fixed five entries to one V2 consumption record.
type SandboxDraftEvidenceMetadata struct {
	Domain                        string                       `json:"domain"`
	SchemaVersion                 string                       `json:"schema_version"`
	TenantID                      string                       `json:"tenant_id"`
	WorkspaceID                   string                       `json:"workspace_id"`
	ConsumerSubject               string                       `json:"consumer_subject"`
	IdempotencyKey                string                       `json:"idempotency_key"`
	ProposalID                    string                       `json:"proposal_id"`
	ProposalContentHash           string                       `json:"proposal_content_hash"`
	ConsumptionHash               string                       `json:"consumption_hash"`
	ConsumptionSignatureAlgorithm string                       `json:"consumption_signature_algorithm"`
	ConsumptionSignature          string                       `json:"consumption_signature"`
	PlanHash                      string                       `json:"plan_hash"`
	PolicyHash                    string                       `json:"policy_hash"`
	Profile                       SandboxDraftEvidenceProfile  `json:"profile"`
	InputHash                     string                       `json:"input_hash"`
	Artifact                      SandboxDraftEvidenceArtifact `json:"artifact"`
	Receipt                       SandboxDraftEvidenceReceipt  `json:"receipt"`
}

// SandboxDraftEvidenceEnvelope is the typed current data-plane archive
// profile. Archive is passed as bytes rather than decoded JSON by design.
type SandboxDraftEvidenceEnvelope struct {
	Metadata    SandboxDraftEvidenceMetadata `json:"metadata"`
	Manifest    evidencepack.Manifest        `json:"manifest"`
	Archive     []byte                       `json:"-"`
	ArchiveHash string                       `json:"archive_hash"`
}

// SandboxDraftEvidenceSourceSnapshot keeps source-control identity distinct
// from the workload that consumed the grant. Proposal must be the exact result
// of SandboxDraftProposalSource.LoadSandboxDraftProposal called by the private
// authenticated source boundary with this identity; this verifier accepts no
// browser or transport identity fields and does not perform that lookup.
type SandboxDraftEvidenceSourceSnapshot struct {
	ControlIdentity ControlIdentity
	Proposal        SandboxDraftProposal
}

// SandboxDraftEvidenceVerificationInput contains the trusted runtime inputs.
// ExpectedConsumer is the authenticated workload identity; Source is a
// separate private source snapshot and must not be derived from that workload.
type SandboxDraftEvidenceVerificationInput struct {
	Envelope         SandboxDraftEvidenceEnvelope
	ExpectedConsumer ConsumerIdentity
	Source           SandboxDraftEvidenceSourceSnapshot
}

// SandboxDraftEvidenceVerifier verifies only the portable inner archive. It
// neither issues nor consumes grants, dispatches work, accepts browser input,
// or validates any outer EvidencePack receipt authority.
type SandboxDraftEvidenceVerifier struct {
	grantVerifier     GrantSignatureVerifier
	kernelIdentity    string
	kernelTrustRootID string
}

func NewSandboxDraftEvidenceVerifier(grantVerifier GrantSignatureVerifier, kernelIdentity, kernelTrustRootID string) (*SandboxDraftEvidenceVerifier, error) {
	if grantVerifier == nil || !validToken(kernelIdentity) || !validToken(kernelTrustRootID) {
		return nil, sandboxDraftEvidenceRejected("pinned grant verifier, kernel identity, and trust root are required")
	}
	return &SandboxDraftEvidenceVerifier{
		grantVerifier: grantVerifier, kernelIdentity: kernelIdentity, kernelTrustRootID: kernelTrustRootID,
	}, nil
}

// Verify is pure: it checks only the supplied envelope, the pinned verifier,
// and the immutable source snapshot. It does not load source records or create
// identity from context; callers must perform the private authenticated lookup
// before invoking it.
func (v *SandboxDraftEvidenceVerifier) Verify(input SandboxDraftEvidenceVerificationInput) error {
	if v == nil || v.grantVerifier == nil || !validToken(v.kernelIdentity) || !validToken(v.kernelTrustRootID) {
		return sandboxDraftEvidenceRejected("verifier is not configured")
	}
	if err := validateSandboxDraftEvidenceConsumer(input.ExpectedConsumer); err != nil {
		return err
	}
	if err := validateSandboxDraftEvidenceSource(input.Source, input.ExpectedConsumer); err != nil {
		return err
	}
	return v.verifyEnvelope(input.Envelope, input.ExpectedConsumer, input.Source.Proposal)
}

func (v *SandboxDraftEvidenceVerifier) verifyEnvelope(envelope SandboxDraftEvidenceEnvelope, consumer ConsumerIdentity, proposal SandboxDraftProposal) error {
	metadata := envelope.Metadata
	if err := metadata.validate(); err != nil || len(envelope.Archive) == 0 || !validSHA256(envelope.ArchiveHash) ||
		evidencepack.HashContent(envelope.Archive) != envelope.ArchiveHash {
		return sandboxDraftEvidenceRejected("metadata or archive hash is invalid")
	}
	if metadata.TenantID != consumer.TenantID || metadata.WorkspaceID != consumer.WorkspaceID || metadata.ConsumerSubject != consumer.Subject ||
		metadata.ProposalID != proposal.ProposalID || proposal.BindingRef != "sandbox-draft:"+metadata.ProposalID ||
		metadata.ProposalContentHash != proposal.IntentHash || metadata.PlanHash != proposal.PlanHash || metadata.PolicyHash != proposal.PolicyHash ||
		metadata.Profile.TemplateID != proposal.TemplateID || metadata.Profile.TemplateDigest != proposal.TemplateDigest ||
		metadata.InputHash != sandboxDraftEvidenceInputHash(proposal, metadata.Profile) {
		return sandboxDraftEvidenceRejected("metadata does not match the source proposal or expected workload")
	}

	contents, err := evidencepack.Unarchive(envelope.Archive)
	if err != nil {
		return sandboxDraftEvidenceRejected("archive cannot be read")
	}
	canonicalArchive, err := evidencepack.Archive(contents)
	if err != nil || !bytes.Equal(canonicalArchive, envelope.Archive) {
		return sandboxDraftEvidenceRejected("archive is not the deterministic five-entry profile")
	}

	manifestJSON, ok := contents["manifest.json"]
	if !ok {
		return sandboxDraftEvidenceRejected("manifest is absent")
	}
	var manifest evidencepack.Manifest
	if err := decodeSandboxDraftEvidenceJSON(manifestJSON, &manifest); err != nil || !reflect.DeepEqual(manifest, envelope.Manifest) {
		return sandboxDraftEvidenceRejected("manifest does not match the envelope")
	}
	if manifest.Version != evidencepack.ManifestVersion || manifest.IntentID != metadata.ProposalID || manifest.PolicyHash != metadata.PolicyHash ||
		manifest.ActorDID != consumer.Subject || manifest.PackID != sandboxDraftEvidencePackID(metadata) {
		return sandboxDraftEvidenceRejected("manifest binding is invalid")
	}
	manifestHash, err := evidencepack.ComputeManifestHash(&manifest)
	if err != nil || !validSHA256(manifest.ManifestHash) || manifestHash != manifest.ManifestHash {
		return sandboxDraftEvidenceRejected("manifest hash is invalid")
	}
	merkleRoot, err := evidencepack.ComputeEntriesMerkleRoot(manifest.Entries)
	if err != nil || manifest.EntriesMerkleRoot != merkleRoot {
		return sandboxDraftEvidenceRejected("manifest merkle root is invalid")
	}

	expectedEntries := map[string]string{
		sandboxDraftArtifactPath:             "text/markdown; charset=utf-8",
		sandboxDraftConsumptionPath:          "application/json",
		sandboxDraftConsumptionSignaturePath: "application/json",
		sandboxDraftBindingPath:              "application/json",
		sandboxDraftReceiptPath:              "application/json",
	}
	if len(manifest.Entries) != len(expectedEntries) || len(contents) != len(expectedEntries)+1 {
		return sandboxDraftEvidenceRejected("archive entry count is invalid")
	}
	seen := make(map[string]struct{}, len(expectedEntries))
	for _, entry := range manifest.Entries {
		contentType, ok := expectedEntries[entry.Path]
		content, present := contents[entry.Path]
		if !ok || !present || entry.ContentType != contentType || entry.Size != int64(len(content)) ||
			!validSHA256(entry.ContentHash) || entry.ContentHash != evidencepack.HashContent(content) {
			return sandboxDraftEvidenceRejected("archive entry hash or profile is invalid")
		}
		seen[entry.Path] = struct{}{}
	}
	if len(seen) != len(expectedEntries) {
		return sandboxDraftEvidenceRejected("archive entries are duplicated or incomplete")
	}

	if !bytes.Equal(contents[sandboxDraftArtifactPath], []byte(metadata.Artifact.RedactedBodyMarkdown)) {
		return sandboxDraftEvidenceRejected("artifact bytes do not match metadata")
	}
	var receipt SandboxDraftEvidenceReceipt
	if err := decodeSandboxDraftEvidenceJSON(contents[sandboxDraftReceiptPath], &receipt); err != nil || receipt != metadata.Receipt ||
		!sandboxDraftEvidenceCanonicalContentEquals(contents[sandboxDraftReceiptPath], metadata.Receipt) {
		return sandboxDraftEvidenceRejected("receipt content is invalid")
	}
	var binding sandboxDraftEvidenceBinding
	if err := decodeSandboxDraftEvidenceJSON(contents[sandboxDraftBindingPath], &binding); err != nil || binding != metadata.binding() ||
		!sandboxDraftEvidenceCanonicalContentEquals(contents[sandboxDraftBindingPath], metadata.binding()) {
		return sandboxDraftEvidenceRejected("binding content is invalid")
	}

	var consumption contracts.ApprovalGrantConsumption
	if err := decodeSandboxDraftEvidenceJSON(contents[sandboxDraftConsumptionPath], &consumption); err != nil ||
		consumption.SchemaVersion != contracts.ApprovalGrantConsumptionSchemaV2 || consumption.ContractVersion != contracts.ApprovalGrantConsumptionContractV2 ||
		consumption.Validate() != nil {
		return sandboxDraftEvidenceRejected("V2 consumption is invalid")
	}
	sealedConsumption, err := consumption.Seal()
	canonicalConsumption, canonicalErr := canonicalize.JCS(consumption)
	if err != nil || canonicalErr != nil || sealedConsumption.ConsumptionHash != consumption.ConsumptionHash ||
		consumption.ConsumptionHash != metadata.ConsumptionHash || !bytes.Equal(contents[sandboxDraftConsumptionPath], canonicalConsumption) {
		return sandboxDraftEvidenceRejected("consumption canonical content is invalid")
	}
	var signature sandboxDraftConsumptionSignature
	if err := decodeSandboxDraftEvidenceJSON(contents[sandboxDraftConsumptionSignaturePath], &signature); err != nil || signature.validate() != nil ||
		signature.Algorithm != metadata.ConsumptionSignatureAlgorithm || signature.Signature != metadata.ConsumptionSignature ||
		!sandboxDraftEvidenceCanonicalContentEquals(contents[sandboxDraftConsumptionSignaturePath], signature) {
		return sandboxDraftEvidenceRejected("consumption signature envelope is invalid")
	}
	if err := v.verifyConsumption(consumption, metadata, consumer, proposal); err != nil {
		return err
	}
	if !manifest.CreatedAt.Equal(consumption.ConsumedAt.UTC()) {
		return sandboxDraftEvidenceRejected("manifest timestamp is not bound to consumption")
	}
	return nil
}

func (v *SandboxDraftEvidenceVerifier) verifyConsumption(consumption contracts.ApprovalGrantConsumption, metadata SandboxDraftEvidenceMetadata, consumer ConsumerIdentity, proposal SandboxDraftProposal) error {
	if consumption.TenantID != consumer.TenantID || consumption.WorkspaceID != consumer.WorkspaceID || consumption.ConsumedBy != consumer.Subject ||
		consumption.Audience != contracts.ApprovalGrantAudiencePolicyDraftSandboxExecutorV1 ||
		consumption.PackID != contracts.ApprovalGrantPackIDPolicyDraftSandbox || consumption.Action != contracts.ApprovalGrantActionPolicyDraftSandbox ||
		consumption.IntentHash != proposal.IntentHash || consumption.EffectHash != proposal.EffectHash || consumption.PlanHash != proposal.PlanHash ||
		consumption.PackVersion != proposal.PackVersion || consumption.PackManifestHash != proposal.PackManifestHash ||
		consumption.PolicyVersion != proposal.PolicyVersion || consumption.PolicyEpoch != proposal.PolicyEpoch || consumption.PolicyHash != proposal.PolicyHash ||
		consumption.ServerIdentity != v.kernelIdentity || consumption.KernelTrustRootID != v.kernelTrustRootID {
		return sandboxDraftEvidenceRejected("consumption tuple, workload, kernel identity, or trust root mismatch")
	}
	if err := v.grantVerifier.VerifyGrantConsumptionSignature(consumption, metadata.ConsumptionSignatureAlgorithm, metadata.ConsumptionSignature); err != nil {
		return sandboxDraftEvidenceRejected("pinned consumption signature verification failed")
	}
	return nil
}

func validateSandboxDraftEvidenceConsumer(identity ConsumerIdentity) error {
	for field, value := range map[string]string{
		"consumer subject": identity.Subject, "tenant": identity.TenantID, "workspace": identity.WorkspaceID, "audience": identity.Audience,
	} {
		if !validToken(value) {
			return sandboxDraftEvidenceRejected(field + " is required")
		}
	}
	if identity.Audience != contracts.ApprovalGrantAudiencePolicyDraftSandboxExecutorV1 {
		return sandboxDraftEvidenceRejected("consumer audience is invalid")
	}
	return nil
}

func validateSandboxDraftEvidenceSource(source SandboxDraftEvidenceSourceSnapshot, consumer ConsumerIdentity) error {
	for field, value := range map[string]string{
		"source subject": source.ControlIdentity.Subject, "source tenant": source.ControlIdentity.TenantID, "source workspace": source.ControlIdentity.WorkspaceID,
	} {
		if !validToken(value) {
			return sandboxDraftEvidenceRejected(field + " is required")
		}
	}
	if source.ControlIdentity.TenantID != consumer.TenantID || source.ControlIdentity.WorkspaceID != consumer.WorkspaceID ||
		source.Proposal.TenantID != consumer.TenantID || source.Proposal.WorkspaceID != consumer.WorkspaceID ||
		source.Proposal.Subject != source.ControlIdentity.Subject {
		return sandboxDraftEvidenceRejected("private source identity or proposal scope mismatch")
	}
	if err := source.Proposal.Validate(); err != nil {
		return sandboxDraftEvidenceRejected("source proposal is invalid")
	}
	return nil
}

func (m SandboxDraftEvidenceMetadata) validate() error {
	if m.Domain != SandboxDraftEvidenceMetadataDomainV1 || m.SchemaVersion != SandboxDraftEvidenceMetadataSchemaV1 ||
		m.Profile.validate() != nil || m.Artifact.validate() != nil || m.Receipt.validate() != nil {
		return sandboxDraftEvidenceRejected("metadata profile is invalid")
	}
	for field, value := range map[string]string{
		"tenant": m.TenantID, "workspace": m.WorkspaceID, "consumer subject": m.ConsumerSubject, "idempotency key": m.IdempotencyKey, "proposal": m.ProposalID,
	} {
		if !validToken(value) {
			return sandboxDraftEvidenceRejected(field + " is required")
		}
	}
	for _, value := range []string{m.ProposalContentHash, m.ConsumptionHash, m.PlanHash, m.PolicyHash, m.InputHash} {
		if !validSHA256(value) {
			return sandboxDraftEvidenceRejected("metadata hash is invalid")
		}
	}
	if m.ConsumptionSignatureAlgorithm != GrantSignatureEd25519 || !validEd25519Signature(m.ConsumptionSignature) ||
		m.Receipt.TenantID != m.TenantID || m.Receipt.WorkspaceID != m.WorkspaceID || m.Receipt.ConsumerSubject != m.ConsumerSubject ||
		m.Receipt.IdempotencyKey != m.IdempotencyKey || m.Receipt.ProposalID != m.ProposalID ||
		m.Receipt.ProposalContentHash != m.ProposalContentHash || m.Receipt.ConsumptionHash != m.ConsumptionHash ||
		m.Receipt.TemplateID != m.Profile.TemplateID || m.Receipt.TemplateDigest != m.Profile.TemplateDigest ||
		m.Receipt.InputHash != m.InputHash || m.Receipt.ArtifactType != m.Artifact.ArtifactType ||
		m.Receipt.ArtifactContentHash != m.Artifact.ContentHash {
		return sandboxDraftEvidenceRejected("metadata receipt binding is invalid")
	}
	return nil
}

func (p SandboxDraftEvidenceProfile) validate() error {
	if p.TemplateID != SandboxDraftEvidenceTemplateID || !validSHA256(p.TemplateDigest) || !p.DefaultDenyEgress || !p.NoMounts || !p.NoSecrets {
		return sandboxDraftEvidenceRejected("sandbox profile is invalid")
	}
	return nil
}

func (a SandboxDraftEvidenceArtifact) validate() error {
	if a.ArtifactType != SandboxDraftEvidenceArtifactTypeV1 || !validSHA256(a.ContentHash) || strings.TrimSpace(a.RedactedBodyMarkdown) == "" ||
		!utf8.ValidString(a.RedactedBodyMarkdown) || len(a.RedactedBodyMarkdown) > 1<<20 ||
		a.ContentHash != evidencepack.HashContent([]byte(a.RedactedBodyMarkdown)) {
		return sandboxDraftEvidenceRejected("artifact is invalid")
	}
	return nil
}

func (r SandboxDraftEvidenceReceipt) validate() error {
	if r.Domain != SandboxDraftReceiptDomainV1 || r.SchemaVersion != SandboxDraftReceiptSchemaV1 || r.TemplateID != SandboxDraftEvidenceTemplateID ||
		r.ArtifactType != SandboxDraftEvidenceArtifactTypeV1 {
		return sandboxDraftEvidenceRejected("receipt profile is invalid")
	}
	for _, value := range []string{r.TenantID, r.WorkspaceID, r.ConsumerSubject, r.IdempotencyKey, r.ProposalID, r.TemplateID} {
		if !validToken(value) {
			return sandboxDraftEvidenceRejected("receipt token is invalid")
		}
	}
	for _, value := range []string{r.ProposalContentHash, r.ConsumptionHash, r.TemplateDigest, r.InputHash, r.ArtifactContentHash} {
		if !validSHA256(value) {
			return sandboxDraftEvidenceRejected("receipt hash is invalid")
		}
	}
	return nil
}

type sandboxDraftEvidenceBinding struct {
	Action              string                      `json:"action"`
	Audience            string                      `json:"audience"`
	PackID              string                      `json:"pack_id"`
	ProposalID          string                      `json:"proposal_id"`
	ProposalContentHash string                      `json:"proposal_content_hash"`
	ConsumptionHash     string                      `json:"consumption_hash"`
	PlanHash            string                      `json:"plan_hash"`
	PolicyHash          string                      `json:"policy_hash"`
	Profile             SandboxDraftEvidenceProfile `json:"profile"`
	ArtifactType        string                      `json:"artifact_type"`
	ArtifactContentHash string                      `json:"artifact_content_hash"`
}

func (m SandboxDraftEvidenceMetadata) binding() sandboxDraftEvidenceBinding {
	return sandboxDraftEvidenceBinding{
		Action:     contracts.ApprovalGrantActionPolicyDraftSandbox,
		Audience:   contracts.ApprovalGrantAudiencePolicyDraftSandboxExecutorV1,
		PackID:     contracts.ApprovalGrantPackIDPolicyDraftSandbox,
		ProposalID: m.ProposalID, ProposalContentHash: m.ProposalContentHash, ConsumptionHash: m.ConsumptionHash,
		PlanHash: m.PlanHash, PolicyHash: m.PolicyHash, Profile: m.Profile,
		ArtifactType: m.Artifact.ArtifactType, ArtifactContentHash: m.Artifact.ContentHash,
	}
}

type sandboxDraftConsumptionSignature struct {
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}

func (s sandboxDraftConsumptionSignature) validate() error {
	if s.Algorithm != GrantSignatureEd25519 || !validEd25519Signature(s.Signature) {
		return sandboxDraftEvidenceRejected("consumption signature is invalid")
	}
	return nil
}

func sandboxDraftEvidenceInputHash(proposal SandboxDraftProposal, profile SandboxDraftEvidenceProfile) string {
	payload, err := canonicalize.JCS(struct {
		ProposalID          string                      `json:"proposal_id"`
		ProposalContentHash string                      `json:"proposal_content_hash"`
		IntentHash          string                      `json:"intent_hash"`
		EffectHash          string                      `json:"effect_hash"`
		PlanHash            string                      `json:"plan_hash"`
		Profile             SandboxDraftEvidenceProfile `json:"profile"`
	}{
		ProposalID: proposal.ProposalID, ProposalContentHash: proposal.IntentHash,
		IntentHash: proposal.IntentHash, EffectHash: proposal.EffectHash, PlanHash: proposal.PlanHash, Profile: profile,
	})
	if err != nil {
		return ""
	}
	return "sha256:" + canonicalize.HashBytes(payload)
}

func sandboxDraftEvidencePackID(metadata SandboxDraftEvidenceMetadata) string {
	sum := sha256.Sum256([]byte(metadata.TenantID + "\x00" + metadata.WorkspaceID + "\x00" + metadata.IdempotencyKey + "\x00" + metadata.ConsumptionHash))
	return "sandbox-draft-" + hex.EncodeToString(sum[:])
}

func decodeSandboxDraftEvidenceJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

// sandboxDraftEvidenceCanonicalContentEquals accepts the current profile's
// indented JSON but requires its canonical semantic content to be exact.
func sandboxDraftEvidenceCanonicalContentEquals(raw []byte, expected any) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var actual any
	if err := decoder.Decode(&actual); err != nil {
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return false
	}
	if _, ok := actual.(map[string]any); !ok {
		return false
	}
	actualCanonical, err := canonicalize.JCS(actual)
	if err != nil {
		return false
	}
	expectedCanonical, err := canonicalize.JCS(expected)
	return err == nil && bytes.Equal(actualCanonical, expectedCanonical)
}

func sandboxDraftEvidenceRejected(message string) error {
	return fmt.Errorf("%w: %s", ErrSandboxDraftEvidenceRejected, message)
}
