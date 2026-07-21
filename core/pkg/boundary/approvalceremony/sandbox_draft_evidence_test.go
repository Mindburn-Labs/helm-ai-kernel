package approvalceremony

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	corecrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
)

func TestSandboxDraftEvidenceVerifierAcceptsCurrentFiveEntryProfile(t *testing.T) {
	fixture := newSandboxDraftEvidenceFixture(t)
	if fixture.input.ExpectedConsumer.Subject == fixture.input.Source.ControlIdentity.Subject {
		t.Fatal("fixture must keep workload and source-control identities distinct")
	}
	if err := fixture.verifier.Verify(fixture.input); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestSandboxDraftEvidenceVerifierDoesNotTreatSourceServerIdentityAsKernelIdentity(t *testing.T) {
	fixture := newSandboxDraftEvidenceFixture(t)
	proposal := fixture.input.Source.Proposal
	proposal.ServerIdentity = "spiffe://helm/control-plane"
	fixture.input.Source.Proposal = proposal
	if err := fixture.verifier.Verify(fixture.input); err != nil {
		t.Fatalf("Verify() rejected a syntactically valid source server identity: %v", err)
	}
}

func TestSandboxDraftEvidenceVerifierRejectsMismatches(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*sandboxDraftEvidenceFixture)
	}{
		{
			name: "v1 consumption",
			mutate: func(f *sandboxDraftEvidenceFixture) {
				consumption := f.consumption
				consumption.SchemaVersion = contracts.ApprovalGrantConsumptionSchemaV1
				consumption.ContractVersion = contracts.ApprovalGrantConsumptionContractV1
				consumption.Audience = "legacy-audience"
				consumption.PackID = "legacy-pack"
				consumption.Action = contracts.ApprovalGrantActionInstall
				f.rebuild(consumption)
			},
		},
		{
			name: "tenant substitution",
			mutate: func(f *sandboxDraftEvidenceFixture) {
				f.input.ExpectedConsumer.TenantID = "tenant-b"
			},
		},
		{
			name: "workspace substitution",
			mutate: func(f *sandboxDraftEvidenceFixture) {
				f.input.ExpectedConsumer.WorkspaceID = "workspace-b"
			},
		},
		{
			name: "workload subject substitution",
			mutate: func(f *sandboxDraftEvidenceFixture) {
				f.input.ExpectedConsumer.Subject = "spiffe://helm/data-plane-b"
			},
		},
		{
			name: "source control subject substitution",
			mutate: func(f *sandboxDraftEvidenceFixture) {
				f.input.Source.ControlIdentity.Subject = "spiffe://helm/control-plane-b"
			},
		},
		{
			name: "source plan mismatch",
			mutate: func(f *sandboxDraftEvidenceFixture) {
				proposal := f.input.Source.Proposal
				proposal.TemplateDigest = sandboxDraftEvidenceHash("e")
				proposal.PlanCanonicalJSON = []byte(`{"default_deny":true,"egress":[],"mounts":[],"proposal_id":"proposal-a","secrets":[],"template_digest":"` + proposal.TemplateDigest + `","template_id":"draft_policy"}`)
				proposal.PlanHash = canonicalize.ComputeArtifactHash(proposal.PlanCanonicalJSON)
				f.input.Source.Proposal = proposal
			},
		},
		{
			name: "source intent mismatch",
			mutate: func(f *sandboxDraftEvidenceFixture) {
				proposal := f.input.Source.Proposal
				proposal.IntentCanonicalJSON = []byte(`{"objective":"different-draft","proposal_id":"proposal-a"}`)
				proposal.IntentHash = canonicalize.ComputeArtifactHash(proposal.IntentCanonicalJSON)
				f.input.Source.Proposal = proposal
			},
		},
		{
			name: "source effect mismatch",
			mutate: func(f *sandboxDraftEvidenceFixture) {
				consumption := f.consumption
				consumption.EffectHash = sandboxDraftEvidenceHash("e")
				f.rebuild(consumption)
			},
		},
		{
			name: "source policy mismatch",
			mutate: func(f *sandboxDraftEvidenceFixture) {
				proposal := f.input.Source.Proposal
				proposal.PolicyHash = sandboxDraftEvidenceHash("e")
				f.input.Source.Proposal = proposal
			},
		},
		{
			name: "source pack mismatch",
			mutate: func(f *sandboxDraftEvidenceFixture) {
				proposal := f.input.Source.Proposal
				proposal.PackVersion = "2.0.0"
				f.input.Source.Proposal = proposal
			},
		},
		{
			name: "archive tamper",
			mutate: func(f *sandboxDraftEvidenceFixture) {
				f.input.Envelope.Archive[len(f.input.Envelope.Archive)/2] ^= 0x01
			},
		},
		{
			name: "consumption signature mismatch",
			mutate: func(f *sandboxDraftEvidenceFixture) {
				f.rebuildWithSignature(f.consumption, strings.Repeat("0", ed25519.SignatureSize*2))
			},
		},
		{
			name: "kernel trust root mismatch",
			mutate: func(f *sandboxDraftEvidenceFixture) {
				verifier, err := NewSandboxDraftEvidenceVerifier(f.grantVerifier, "spiffe://helm/kernel-a", "kernel-root-b")
				if err != nil {
					f.t.Fatalf("NewSandboxDraftEvidenceVerifier() error = %v", err)
				}
				f.verifier = verifier
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSandboxDraftEvidenceFixture(t)
			test.mutate(fixture)
			if err := fixture.verifier.Verify(fixture.input); !errors.Is(err, ErrSandboxDraftEvidenceRejected) {
				t.Fatalf("Verify() error = %v, want ErrSandboxDraftEvidenceRejected", err)
			}
		})
	}
}

type sandboxDraftEvidenceFixture struct {
	t             *testing.T
	verifier      *SandboxDraftEvidenceVerifier
	grantVerifier GrantSignatureVerifier
	signer        *corecrypto.Ed25519Signer
	proposal      SandboxDraftProposal
	consumer      ConsumerIdentity
	consumption   contracts.ApprovalGrantConsumption
	input         SandboxDraftEvidenceVerificationInput
}

func newSandboxDraftEvidenceFixture(t *testing.T) *sandboxDraftEvidenceFixture {
	t.Helper()
	proposal := sandboxDraftEvidenceProposal()
	consumer := ConsumerIdentity{
		TenantID: "tenant-a", WorkspaceID: "workspace-a", Subject: "spiffe://helm/data-plane-a",
		Audience: contracts.ApprovalGrantAudiencePolicyDraftSandboxExecutorV1,
	}
	signer := corecrypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)), "sandbox-evidence-key",
	)
	consumption := sandboxDraftEvidenceConsumption(proposal, consumer)
	consumption, signature := sandboxDraftEvidenceSealAndSign(t, signer, consumption)
	grantVerifier, err := NewEd25519GrantSignatureVerifier(signer.PublicKeyBytes(), consumption.SigningKeyRef, consumption.KernelTrustRootID)
	if err != nil {
		t.Fatalf("NewEd25519GrantSignatureVerifier() error = %v", err)
	}
	verifier, err := NewSandboxDraftEvidenceVerifier(grantVerifier, consumption.ServerIdentity, consumption.KernelTrustRootID)
	if err != nil {
		t.Fatalf("NewSandboxDraftEvidenceVerifier() error = %v", err)
	}
	fixture := &sandboxDraftEvidenceFixture{
		t: t, verifier: verifier, grantVerifier: grantVerifier, signer: signer, proposal: proposal, consumer: consumer, consumption: consumption,
	}
	fixture.input = SandboxDraftEvidenceVerificationInput{
		Envelope:         sandboxDraftEvidenceEnvelope(t, proposal, consumer, consumption, signature),
		ExpectedConsumer: consumer,
		Source: SandboxDraftEvidenceSourceSnapshot{
			ControlIdentity: ControlIdentity{TenantID: proposal.TenantID, WorkspaceID: proposal.WorkspaceID, Subject: proposal.Subject},
			Proposal:        proposal,
		},
	}
	return fixture
}

func (f *sandboxDraftEvidenceFixture) rebuild(consumption contracts.ApprovalGrantConsumption) {
	f.t.Helper()
	consumption, signature := sandboxDraftEvidenceSealAndSign(f.t, f.signer, consumption)
	f.rebuildWithSignature(consumption, signature)
}

func (f *sandboxDraftEvidenceFixture) rebuildWithSignature(consumption contracts.ApprovalGrantConsumption, signature string) {
	f.t.Helper()
	f.consumption = consumption
	f.input.Envelope = sandboxDraftEvidenceEnvelope(f.t, f.proposal, f.consumer, consumption, signature)
}

func sandboxDraftEvidenceProposal() SandboxDraftProposal {
	templateDigest := sandboxDraftEvidenceHash("d")
	plan := []byte(`{"default_deny":true,"egress":[],"mounts":[],"proposal_id":"proposal-a","secrets":[],"template_digest":"` + templateDigest + `","template_id":"draft_policy"}`)
	intent := []byte(`{"objective":"draft-policy","proposal_id":"proposal-a"}`)
	effect := []byte(`{"effect_type":"policy.draft.sandbox","execution":"not_dispatched","scope":"sandbox"}`)
	return SandboxDraftProposal{
		SchemaVersion: SandboxDraftProposalSchemaV1, ContractVersion: SandboxDraftProposalContractV1,
		BindingRef: "sandbox-draft:proposal-a", ProposalID: "proposal-a", TenantID: "tenant-a", WorkspaceID: "workspace-a",
		Subject: "spiffe://helm/control-plane-a", TemplateID: SandboxDraftEvidenceTemplateID, TemplateDigest: templateDigest,
		PlanCanonicalJSON: plan, PlanHash: canonicalize.ComputeArtifactHash(plan),
		IntentCanonicalJSON: intent, IntentHash: canonicalize.ComputeArtifactHash(intent),
		EffectCanonicalJSON: effect, EffectHash: canonicalize.ComputeArtifactHash(effect),
		PackVersion: "1.0.0", PackManifestHash: sandboxDraftEvidenceHash("a"), PolicyVersion: "policy-v1", PolicyEpoch: "epoch-1",
		PolicyHash: sandboxDraftEvidenceHash("b"), AuthoritySource: "spiffe://helm/authority/approvers", AuthorityVersion: "authority-v1",
		AuthoritySnapshotHash: sandboxDraftEvidenceHash("c"), RequiredRole: "policy-admin", Quorum: 2,
		ServerIdentity: "spiffe://helm/kernel-a",
	}
}

func sandboxDraftEvidenceConsumption(proposal SandboxDraftProposal, consumer ConsumerIdentity) contracts.ApprovalGrantConsumption {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	return contracts.ApprovalGrantConsumption{
		SchemaVersion: contracts.ApprovalGrantConsumptionSchemaV2, ContractVersion: contracts.ApprovalGrantConsumptionContractV2,
		ApprovalID: "approval-a", GrantID: "grant-a", GrantHash: sandboxDraftEvidenceHash("1"),
		TenantID: consumer.TenantID, WorkspaceID: consumer.WorkspaceID, Audience: consumer.Audience, ConsumedBy: consumer.Subject,
		PackID: contracts.ApprovalGrantPackIDPolicyDraftSandbox, PackVersion: proposal.PackVersion, PackManifestHash: proposal.PackManifestHash,
		Action: contracts.ApprovalGrantActionPolicyDraftSandbox, IntentHash: proposal.IntentHash, EffectHash: proposal.EffectHash, PlanHash: proposal.PlanHash,
		PolicyVersion: proposal.PolicyVersion, PolicyEpoch: proposal.PolicyEpoch, PolicyHash: proposal.PolicyHash,
		ServerIdentity: proposal.ServerIdentity, KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kms://helm/approval-a",
		GrantIssuedAt: now.Add(-time.Minute), GrantExpiresAt: now.Add(time.Minute), ConsumedAt: now,
	}
}

func sandboxDraftEvidenceSealAndSign(t *testing.T, signer *corecrypto.Ed25519Signer, consumption contracts.ApprovalGrantConsumption) (contracts.ApprovalGrantConsumption, string) {
	t.Helper()
	consumption.ConsumptionHash = ""
	sealed, err := consumption.Seal()
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	signature, err := SignApprovalGrantConsumption(sealed, signer)
	if err != nil {
		t.Fatalf("SignApprovalGrantConsumption() error = %v", err)
	}
	return sealed, signature
}

func sandboxDraftEvidenceEnvelope(t *testing.T, proposal SandboxDraftProposal, consumer ConsumerIdentity, consumption contracts.ApprovalGrantConsumption, signature string) SandboxDraftEvidenceEnvelope {
	t.Helper()
	profile := SandboxDraftEvidenceProfile{
		TemplateID: proposal.TemplateID, TemplateDigest: proposal.TemplateDigest,
		DefaultDenyEgress: true, NoMounts: true, NoSecrets: true,
	}
	artifact := SandboxDraftEvidenceArtifact{
		ArtifactType: SandboxDraftEvidenceArtifactTypeV1, RedactedBodyMarkdown: "# Draft policy\n\nNo external dispatch.\n",
	}
	artifact.ContentHash = evidencepack.HashContent([]byte(artifact.RedactedBodyMarkdown))
	inputHash := sandboxDraftEvidenceInputHash(proposal, profile)
	receipt := SandboxDraftEvidenceReceipt{
		Domain: SandboxDraftReceiptDomainV1, SchemaVersion: SandboxDraftReceiptSchemaV1,
		TenantID: consumer.TenantID, WorkspaceID: consumer.WorkspaceID, ConsumerSubject: consumer.Subject, IdempotencyKey: "request-a",
		ProposalID: proposal.ProposalID, ProposalContentHash: proposal.IntentHash, ConsumptionHash: consumption.ConsumptionHash,
		TemplateID: profile.TemplateID, TemplateDigest: profile.TemplateDigest, InputHash: inputHash,
		ArtifactType: artifact.ArtifactType, ArtifactContentHash: artifact.ContentHash,
	}
	metadata := SandboxDraftEvidenceMetadata{
		Domain: SandboxDraftEvidenceMetadataDomainV1, SchemaVersion: SandboxDraftEvidenceMetadataSchemaV1,
		TenantID: consumer.TenantID, WorkspaceID: consumer.WorkspaceID, ConsumerSubject: consumer.Subject, IdempotencyKey: receipt.IdempotencyKey,
		ProposalID: proposal.ProposalID, ProposalContentHash: proposal.IntentHash, ConsumptionHash: consumption.ConsumptionHash,
		ConsumptionSignatureAlgorithm: GrantSignatureEd25519, ConsumptionSignature: signature, PlanHash: proposal.PlanHash, PolicyHash: proposal.PolicyHash,
		Profile: profile, InputHash: inputHash, Artifact: artifact, Receipt: receipt,
	}
	consumptionJSON, err := canonicalize.JCS(consumption)
	if err != nil {
		t.Fatalf("canonicalize consumption: %v", err)
	}
	signatureJSON, err := canonicalize.JCS(sandboxDraftConsumptionSignature{Algorithm: GrantSignatureEd25519, Signature: signature})
	if err != nil {
		t.Fatalf("canonicalize consumption signature: %v", err)
	}
	builder := evidencepack.NewBuilder(
		sandboxDraftEvidencePackID(metadata), metadata.ConsumerSubject, metadata.ProposalID, metadata.PolicyHash,
	).WithCreatedAt(consumption.ConsumedAt.UTC())
	if err := builder.AddReceipt("sandbox-draft-receipt", receipt); err != nil {
		t.Fatalf("AddReceipt() error = %v", err)
	}
	if err := builder.AddPolicyDecision("sandbox-draft-binding", metadata.binding()); err != nil {
		t.Fatalf("AddPolicyDecision() error = %v", err)
	}
	builder.AddRawEntry(sandboxDraftArtifactPath, "text/markdown; charset=utf-8", []byte(artifact.RedactedBodyMarkdown))
	builder.AddRawEntry(sandboxDraftConsumptionPath, "application/json", consumptionJSON)
	builder.AddRawEntry(sandboxDraftConsumptionSignaturePath, "application/json", signatureJSON)
	manifest, contents, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	sort.Slice(manifest.Entries, func(i, j int) bool { return manifest.Entries[i].Path < manifest.Entries[j].Path })
	manifest.ManifestHash, err = evidencepack.ComputeManifestHash(manifest)
	if err != nil {
		t.Fatalf("ComputeManifestHash() error = %v", err)
	}
	manifest.EntriesMerkleRoot, err = evidencepack.ComputeEntriesMerkleRoot(manifest.Entries)
	if err != nil {
		t.Fatalf("ComputeEntriesMerkleRoot() error = %v", err)
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	contents["manifest.json"] = manifestJSON
	archive, err := evidencepack.Archive(contents)
	if err != nil {
		t.Fatalf("Archive() error = %v", err)
	}
	return SandboxDraftEvidenceEnvelope{Metadata: metadata, Manifest: *manifest, Archive: archive, ArchiveHash: evidencepack.HashContent(archive)}
}

func sandboxDraftEvidenceHash(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}
