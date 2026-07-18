package approvalceremony

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestSandboxDraftBindingProviderDerivesFixedV2Spec(t *testing.T) {
	proposal := sandboxDraftProposalForTest()
	source := &sandboxDraftProposalSourceForTest{proposal: proposal}
	provider, err := NewSandboxDraftBindingProvider(source)
	if err != nil {
		t.Fatal(err)
	}

	identity := ControlIdentity{TenantID: proposal.TenantID, WorkspaceID: proposal.WorkspaceID, Subject: proposal.Subject}
	spec, err := provider.LoadApprovalBinding(withBindingControlIdentity(context.Background(), identity), proposal.TenantID, proposal.WorkspaceID, proposal.BindingRef)
	if err != nil {
		t.Fatalf("LoadApprovalBinding() error = %v", err)
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("derived ChallengeSpec.Validate() error = %v", err)
	}
	if spec.ApprovalGrantSchemaVersion != "approval-grant.v2" ||
		spec.Audience != "helm.policy-draft-sandbox.executor.v1" ||
		spec.PackID != "helm.policy-draft-sandbox" ||
		spec.Action != "policy.draft.sandbox" || spec.Decision != "ALLOW" {
		t.Fatalf("derived fixed V2 scope = %+v", spec)
	}
	if spec.TenantID != proposal.TenantID || spec.WorkspaceID != proposal.WorkspaceID ||
		spec.PlanHash != proposal.PlanHash || spec.IntentHash != proposal.IntentHash || spec.EffectHash != proposal.EffectHash {
		t.Fatalf("derived immutable binding = %+v", spec)
	}
	if source.tenantID != proposal.TenantID || source.workspaceID != proposal.WorkspaceID ||
		source.subject != proposal.Subject || source.bindingRef != proposal.BindingRef {
		t.Fatalf("source lookup scope = tenant=%q workspace=%q subject=%q ref=%q", source.tenantID, source.workspaceID, source.subject, source.bindingRef)
	}
}

func TestSandboxDraftBindingProviderFailsClosedOnIdentityOrSourceMismatch(t *testing.T) {
	proposal := sandboxDraftProposalForTest()
	identity := ControlIdentity{TenantID: proposal.TenantID, WorkspaceID: proposal.WorkspaceID, Subject: proposal.Subject}

	t.Run("missing verified identity", func(t *testing.T) {
		source := &sandboxDraftProposalSourceForTest{proposal: proposal}
		provider, err := NewSandboxDraftBindingProvider(source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provider.LoadApprovalBinding(context.Background(), proposal.TenantID, proposal.WorkspaceID, proposal.BindingRef); !errors.Is(err, ErrSandboxDraftProposalInvalid) {
			t.Fatalf("LoadApprovalBinding() error = %v, want ErrSandboxDraftProposalInvalid", err)
		}
		if source.calls != 0 {
			t.Fatalf("missing identity reached source %d times", source.calls)
		}
	})

	for name, mutate := range map[string]func(*SandboxDraftProposal){
		"tenant substitution":    func(p *SandboxDraftProposal) { p.TenantID = "tenant-b" },
		"workspace substitution": func(p *SandboxDraftProposal) { p.WorkspaceID = "workspace-b" },
		"subject substitution":   func(p *SandboxDraftProposal) { p.Subject = "spiffe://helm/control-b" },
		"reference substitution": func(p *SandboxDraftProposal) { p.BindingRef = "sandbox-draft:proposal-b" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := proposal
			mutate(&candidate)
			source := &sandboxDraftProposalSourceForTest{proposal: candidate}
			provider, err := NewSandboxDraftBindingProvider(source)
			if err != nil {
				t.Fatal(err)
			}
			ctx := withBindingControlIdentity(context.Background(), identity)
			if _, err := provider.LoadApprovalBinding(ctx, proposal.TenantID, proposal.WorkspaceID, proposal.BindingRef); !errors.Is(err, ErrSandboxDraftProposalInvalid) {
				t.Fatalf("LoadApprovalBinding() error = %v, want ErrSandboxDraftProposalInvalid", err)
			}
		})
	}
}

func TestSandboxDraftBindingProviderRejectsNonCanonicalOrMismatchedBytes(t *testing.T) {
	proposal := sandboxDraftProposalForTest()
	identity := ControlIdentity{TenantID: proposal.TenantID, WorkspaceID: proposal.WorkspaceID, Subject: proposal.Subject}

	for name, mutate := range map[string]func(*SandboxDraftProposal){
		"noncanonical plan": func(p *SandboxDraftProposal) {
			p.PlanCanonicalJSON = []byte(`{"template_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "default_deny":true}`)
		},
		"plan hash mismatch": func(p *SandboxDraftProposal) { p.PlanHash = shaRef("f") },
		"invalid intent":     func(p *SandboxDraftProposal) { p.IntentCanonicalJSON = []byte(`not-json`) },
		"nonobject effect":   func(p *SandboxDraftProposal) { p.EffectCanonicalJSON = []byte(`[]`) },
		"uppercase effect hash": func(p *SandboxDraftProposal) {
			p.EffectHash = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := proposal
			mutate(&candidate)
			provider, err := NewSandboxDraftBindingProvider(&sandboxDraftProposalSourceForTest{proposal: candidate})
			if err != nil {
				t.Fatal(err)
			}
			ctx := withBindingControlIdentity(context.Background(), identity)
			if _, err := provider.LoadApprovalBinding(ctx, proposal.TenantID, proposal.WorkspaceID, proposal.BindingRef); !errors.Is(err, ErrSandboxDraftProposalInvalid) {
				t.Fatalf("LoadApprovalBinding() error = %v, want ErrSandboxDraftProposalInvalid", err)
			}
		})
	}
}

func TestSandboxDraftBindingProviderRejectsSandboxSemanticDrift(t *testing.T) {
	proposal := sandboxDraftProposalForTest()
	identity := ControlIdentity{TenantID: proposal.TenantID, WorkspaceID: proposal.WorkspaceID, Subject: proposal.Subject}

	for name, mutate := range map[string]func(*SandboxDraftProposal){
		"binding reference": func(p *SandboxDraftProposal) { p.BindingRef = "proposal-a" },
		"intent proposal": func(p *SandboxDraftProposal) {
			setSandboxDraftIntent(p, `{"objective":"draft-policy","proposal_id":"proposal-b"}`)
		},
		"effect type": func(p *SandboxDraftProposal) {
			setSandboxDraftEffect(p, `{"effect_type":"policy.draft.live","execution":"not_dispatched","scope":"sandbox"}`)
		},
		"effect scope": func(p *SandboxDraftProposal) {
			setSandboxDraftEffect(p, `{"effect_type":"policy.draft.sandbox","execution":"not_dispatched","scope":"live"}`)
		},
		"effect execution": func(p *SandboxDraftProposal) {
			setSandboxDraftEffect(p, `{"effect_type":"policy.draft.sandbox","execution":"dispatched","scope":"sandbox"}`)
		},
		"plan proposal": func(p *SandboxDraftProposal) {
			setSandboxDraftPlan(p, `{"default_deny":true,"egress":[],"mounts":[],"proposal_id":"proposal-b","secrets":[],"template_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","template_id":"template-a"}`)
		},
		"plan template": func(p *SandboxDraftProposal) {
			setSandboxDraftPlan(p, `{"default_deny":true,"egress":[],"mounts":[],"proposal_id":"proposal-a","secrets":[],"template_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","template_id":"template-b"}`)
		},
		"default allow": func(p *SandboxDraftProposal) {
			setSandboxDraftPlan(p, `{"default_deny":false,"egress":[],"mounts":[],"proposal_id":"proposal-a","secrets":[],"template_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","template_id":"template-a"}`)
		},
		"egress": func(p *SandboxDraftProposal) {
			setSandboxDraftPlan(p, `{"default_deny":true,"egress":[{"host":"example.test"}],"mounts":[],"proposal_id":"proposal-a","secrets":[],"template_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","template_id":"template-a"}`)
		},
		"mount": func(p *SandboxDraftProposal) {
			setSandboxDraftPlan(p, `{"default_deny":true,"egress":[],"mounts":[{"path":"/tmp"}],"proposal_id":"proposal-a","secrets":[],"template_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","template_id":"template-a"}`)
		},
		"secret": func(p *SandboxDraftProposal) {
			setSandboxDraftPlan(p, `{"default_deny":true,"egress":[],"mounts":[],"proposal_id":"proposal-a","secrets":[{"name":"token"}],"template_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","template_id":"template-a"}`)
		},
		"extra plan capability": func(p *SandboxDraftProposal) {
			setSandboxDraftPlan(p, `{"default_deny":true,"egress":[],"mounts":[],"proposal_id":"proposal-a","privileged":true,"secrets":[],"template_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","template_id":"template-a"}`)
		},
		"extra effect capability": func(p *SandboxDraftProposal) {
			setSandboxDraftEffect(p, `{"effect_type":"policy.draft.sandbox","execution":"not_dispatched","scope":"sandbox","write":true}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := proposal
			mutate(&candidate)
			provider, err := NewSandboxDraftBindingProvider(&sandboxDraftProposalSourceForTest{proposal: candidate})
			if err != nil {
				t.Fatal(err)
			}
			ctx := withBindingControlIdentity(context.Background(), identity)
			if _, err := provider.LoadApprovalBinding(ctx, candidate.TenantID, candidate.WorkspaceID, candidate.BindingRef); !errors.Is(err, ErrSandboxDraftProposalInvalid) {
				t.Fatalf("LoadApprovalBinding() error = %v, want ErrSandboxDraftProposalInvalid", err)
			}
		})
	}
}

func TestServicePassesVerifiedControlSubjectToSandboxDraftBindingProvider(t *testing.T) {
	proposal := sandboxDraftProposalForTest()
	source := &sandboxDraftProposalSourceForTest{proposal: proposal}
	provider, err := NewSandboxDraftBindingProvider(source)
	if err != nil {
		t.Fatal(err)
	}
	identity := ControlIdentity{TenantID: proposal.TenantID, WorkspaceID: proposal.WorkspaceID, Subject: proposal.Subject}
	ctx := withBindingControlIdentity(context.Background(), identity)
	spec, err := provider.LoadApprovalBinding(ctx, proposal.TenantID, proposal.WorkspaceID, proposal.BindingRef)
	if err != nil {
		t.Fatal(err)
	}
	source.calls = 0
	service, err := newService(
		&serviceTestStore{}, provider, &serviceTestAuthority{store: authorityMetadata(spec)},
		&serviceTestControl{identity: identity}, &serviceTestConsumer{identity: consumerForSpec(spec)},
		crypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)), "sandbox-draft-binding-test"),
		func() time.Time { return time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC) }, bytes.NewReader(make([]byte, 32)),
		ServiceConfig{
			MinHoldDuration: 5 * time.Minute, ChallengeTTL: 10 * time.Minute,
			MaxChallengeLifetime: 20 * time.Minute, GrantTTL: 5 * time.Minute, MaxAssertions: 4,
			ServerIdentity: spec.ServerIdentity, KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kms://helm/approval-a",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	held, err := service.BeginHold(context.Background(), proposal.BindingRef)
	if err != nil {
		t.Fatalf("BeginHold() error = %v", err)
	}
	if held.Spec.ApprovalGrantSchemaVersion != "approval-grant.v2" || source.subject != proposal.Subject {
		t.Fatalf("held spec = %+v, source subject = %q", held.Spec, source.subject)
	}
}

func TestSandboxDraftBindingProviderIssuesV2Grant(t *testing.T) {
	proposal := sandboxDraftProposalForTest()
	source := &sandboxDraftProposalSourceForTest{proposal: proposal}
	provider, err := NewSandboxDraftBindingProvider(source)
	if err != nil {
		t.Fatal(err)
	}
	identity := ControlIdentity{TenantID: proposal.TenantID, WorkspaceID: proposal.WorkspaceID, Subject: proposal.Subject}
	spec, err := provider.LoadApprovalBinding(withBindingControlIdentity(context.Background(), identity), proposal.TenantID, proposal.WorkspaceID, proposal.BindingRef)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	authority, approverKeys := approvalTestAuthority(spec, now)
	config := ServiceConfig{
		MinHoldDuration: 5 * time.Minute, ChallengeTTL: 10 * time.Minute,
		MaxChallengeLifetime: 20 * time.Minute, GrantTTL: 5 * time.Minute, MaxAssertions: 4,
		ServerIdentity: spec.ServerIdentity, KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kms://helm/approval-a",
	}
	service, err := newService(
		&sandboxDraftV2FlowStore{}, provider, &staticAuthorityProvider{store: authority},
		&staticControlProvider{identity: identity}, &staticConsumerProvider{identity: consumerForSpec(spec)},
		crypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)), "sandbox-draft-binding-test"),
		func() time.Time { return now }, bytes.NewReader(bytes.Repeat([]byte{7}, 1024)), config,
	)
	if err != nil {
		t.Fatal(err)
	}
	granted := issueApprovalTestGrant(t, context.Background(), service, spec, approverKeys, &now, config)
	if granted.Grant == nil || granted.Grant.SchemaVersion != "approval-grant.v2" ||
		granted.Grant.Action != "policy.draft.sandbox" || granted.Grant.PlanHash != proposal.PlanHash {
		t.Fatalf("issued V2 grant = %+v", granted.Grant)
	}
}

type sandboxDraftProposalSourceForTest struct {
	proposal    SandboxDraftProposal
	err         error
	calls       int
	tenantID    string
	workspaceID string
	subject     string
	bindingRef  string
}

func (s *sandboxDraftProposalSourceForTest) LoadSandboxDraftProposal(_ context.Context, tenantID, workspaceID, subject, bindingRef string) (SandboxDraftProposal, error) {
	s.calls++
	s.tenantID = tenantID
	s.workspaceID = workspaceID
	s.subject = subject
	s.bindingRef = bindingRef
	return s.proposal, s.err
}

func sandboxDraftProposalForTest() SandboxDraftProposal {
	plan := []byte(`{"default_deny":true,"egress":[],"mounts":[],"proposal_id":"proposal-a","secrets":[],"template_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","template_id":"template-a"}`)
	intent := []byte(`{"objective":"draft-policy","proposal_id":"proposal-a"}`)
	effect := []byte(`{"effect_type":"policy.draft.sandbox","execution":"not_dispatched","scope":"sandbox"}`)
	return SandboxDraftProposal{
		SchemaVersion: SandboxDraftProposalSchemaV1, ContractVersion: SandboxDraftProposalContractV1,
		BindingRef: "sandbox-draft:proposal-a", ProposalID: "proposal-a",
		TenantID: "tenant-a", WorkspaceID: "workspace-a", Subject: "spiffe://helm/control-plane-a",
		TemplateID: "template-a", TemplateDigest: shaRef("d"),
		PlanCanonicalJSON: plan, PlanHash: canonicalize.ComputeArtifactHash(plan),
		IntentCanonicalJSON: intent, IntentHash: canonicalize.ComputeArtifactHash(intent),
		EffectCanonicalJSON: effect, EffectHash: canonicalize.ComputeArtifactHash(effect),
		PackVersion: "1.0.0", PackManifestHash: shaRef("a"),
		PolicyVersion: "policy-v1", PolicyEpoch: "epoch-1", PolicyHash: shaRef("b"),
		AuthoritySource: "spiffe://helm/authority/approvers", AuthorityVersion: "authority-v1",
		AuthoritySnapshotHash: shaRef("c"), RequiredRole: "policy-admin", Quorum: 2,
		ServerIdentity: "spiffe://helm/kernel-a",
	}
}

func setSandboxDraftPlan(proposal *SandboxDraftProposal, raw string) {
	proposal.PlanCanonicalJSON = []byte(raw)
	proposal.PlanHash = canonicalize.ComputeArtifactHash(proposal.PlanCanonicalJSON)
}

func setSandboxDraftIntent(proposal *SandboxDraftProposal, raw string) {
	proposal.IntentCanonicalJSON = []byte(raw)
	proposal.IntentHash = canonicalize.ComputeArtifactHash(proposal.IntentCanonicalJSON)
}

func setSandboxDraftEffect(proposal *SandboxDraftProposal, raw string) {
	proposal.EffectCanonicalJSON = []byte(raw)
	proposal.EffectHash = canonicalize.ComputeArtifactHash(proposal.EffectCanonicalJSON)
}
