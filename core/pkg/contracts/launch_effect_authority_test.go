// quantum_posture: these authorization fixtures exercise classical Ed25519
// signatures only and make no hybrid or post-quantum protection claim.
package contracts_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestLaunchEffectAuthorizationEnvelopeVerifiesAuthorityBoundary(t *testing.T) {
	envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
	if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/launch_effect_envelope.v1.json"), envelope); err != nil {
		t.Fatalf("signed launch authorization envelope rejected by schema: %v", err)
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatalf("signed launch authorization envelope rejected: %v", err)
	}
}

func TestLaunchEffectAuthorizationEnvelopeVerifiesProviderAuthorityBranches(t *testing.T) {
	for fixtureIndex := 0; fixtureIndex < 5; fixtureIndex++ {
		fixtureIndex := fixtureIndex
		fixture := launchInputFixtures()[fixtureIndex]
		t.Run(fixture.effectID, func(t *testing.T) {
			envelope, ctx, _, _, _ := launchEffectAuthorizationFixtureAt(t, fixtureIndex)
			if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
				t.Fatalf("provider authority envelope rejected: %v", err)
			}
		})
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsProviderAuthorityDrift(t *testing.T) {
	tests := []struct {
		name         string
		fixtureIndex int
		mutateInput  func(map[string]any)
		mutate       func(*contracts.LaunchEffectEnvelopeVerificationContext)
		expect       string
	}{
		{
			name:         "provider route resolver missing",
			fixtureIndex: 0,
			mutate: func(ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
				ctx.ResolveRouteBinding = nil
			},
			expect: "source-owned route binding",
		},
		{
			name:         "provider certification changed",
			fixtureIndex: 0,
			mutateInput: func(input map[string]any) {
				input["provider_certification_hash"] = launchHash("f")
			},
			expect: "provider_certification_hash",
		},
		{
			name:         "commercial quote changed",
			fixtureIndex: 2,
			mutateInput: func(input map[string]any) {
				input["base_provider_cost_minor"] = 999
				input["gross_exposure_minor"] = 1199
				input["expected_cash_minor"] = 999
			},
			expect: "approval-bound route quote",
		},
		{
			name:         "provider mutation action changed",
			fixtureIndex: 0,
			mutateInput: func(input map[string]any) {
				input["provider_payload_hash"] = launchHash("f")
			},
			expect: "action or payload",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope, ctx, _, _, _ := launchEffectAuthorizationFixtureAtWithInputMutation(t, test.fixtureIndex, test.mutateInput)
			if test.mutate != nil {
				test.mutate(&ctx)
			}
			if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil || !strings.Contains(err.Error(), test.expect) {
				t.Fatalf("provider authority drift error = %v, want %q", err, test.expect)
			}
		})
	}
}

func TestLaunchEffectAuthorizationEnvelopeBindsVerdictKeyToTrustRoot(t *testing.T) {
	envelope, ctx, privateKey, _ := launchArtifactAuthorizationFixture(t)
	envelope.KernelTrustRootID = "kernel-root-colliding-key-id"
	ctx.Permit.KernelTrustRootID = envelope.KernelTrustRootID
	var err error
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil || !strings.Contains(err.Error(), "verdict key") {
		t.Fatalf("colliding signer key ID under another trust root error = %v", err)
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsFenceReplay(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(contracts.LaunchEffectAuthorizationEnvelope, *contracts.LaunchEffectEnvelopeVerificationContext)
	}{
		{name: "missing source", mutate: func(_ contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveEmergencyFence = nil
		}},
		{name: "active", mutate: func(envelope contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveEmergencyFence = func(string, string) (contracts.LaunchEmergencyFenceSnapshot, error) {
				return contracts.LaunchEmergencyFenceSnapshot{TenantID: envelope.TenantID, WorkspaceID: envelope.WorkspaceID, EffectiveEpoch: envelope.EmergencyFenceEpoch, Active: true}, nil
			}
		}},
		{name: "stop clear epoch", mutate: func(envelope contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveEmergencyFence = func(string, string) (contracts.LaunchEmergencyFenceSnapshot, error) {
				return contracts.LaunchEmergencyFenceSnapshot{TenantID: envelope.TenantID, WorkspaceID: envelope.WorkspaceID, EffectiveEpoch: envelope.EmergencyFenceEpoch + 2}, nil
			}
		}},
		{name: "scope substitution", mutate: func(envelope contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveEmergencyFence = func(string, string) (contracts.LaunchEmergencyFenceSnapshot, error) {
				return contracts.LaunchEmergencyFenceSnapshot{TenantID: envelope.TenantID, WorkspaceID: "workspace-other", EffectiveEpoch: envelope.EmergencyFenceEpoch}, nil
			}
		}},
		{name: "source unavailable", mutate: func(_ contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveEmergencyFence = func(string, string) (contracts.LaunchEmergencyFenceSnapshot, error) {
				return contracts.LaunchEmergencyFenceSnapshot{}, fmt.Errorf("fence store unavailable")
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
			test.mutate(envelope, &ctx)
			if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
				t.Fatal("stale or unavailable emergency fence state was accepted")
			}
		})
	}
}

func TestLaunchEffectAuthorizationEnvelopeConsumesPermitOnce(t *testing.T) {
	envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
		t.Fatal("single-use permit was consumed twice")
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsExpiryBeforeAtomicFinalization(t *testing.T) {
	envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
	ctx.FinalizeDispatch = func(expected contracts.LaunchEffectDispatchFinalization) (contracts.LaunchEffectDispatchFinalizationResult, error) {
		if expected.Permit != ctx.Permit {
			return contracts.LaunchEffectDispatchFinalizationResult{}, fmt.Errorf("permit compare-and-swap binding mismatch")
		}
		return contracts.LaunchEffectDispatchFinalizationResult{CommittedAt: expected.MustCommitBefore}, nil
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil || !strings.Contains(err.Error(), "expired before atomic dispatch finalization") {
		t.Fatalf("dispatch expiry race error = %v", err)
	}
}

func launchArtifactAuthorizationFixture(t *testing.T) (contracts.LaunchEffectAuthorizationEnvelope, contracts.LaunchEffectEnvelopeVerificationContext, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	envelope, ctx, privateKey, publicKey, _ := launchEffectAuthorizationFixtureAt(t, 5)
	return envelope, ctx, privateKey, publicKey
}

func launchEffectAuthorizationFixtureAt(t *testing.T, fixtureIndex int) (contracts.LaunchEffectAuthorizationEnvelope, contracts.LaunchEffectEnvelopeVerificationContext, ed25519.PrivateKey, ed25519.PublicKey, launchRouteFixture) {
	t.Helper()
	return launchEffectAuthorizationFixtureAtWithInputMutation(t, fixtureIndex, nil)
}

func launchEffectAuthorizationFixtureAtWithInputMutation(t *testing.T, fixtureIndex int, mutateInput func(map[string]any)) (contracts.LaunchEffectAuthorizationEnvelope, contracts.LaunchEffectEnvelopeVerificationContext, ed25519.PrivateKey, ed25519.PublicKey, launchRouteFixture) {
	t.Helper()
	fixture := launchInputFixtures()[fixtureIndex]
	input := cloneLaunchInput(t, fixture.input)
	contract := contracts.LookupLaunchMissionEffectPreview(fixture.effectID)
	if contract == nil {
		t.Fatalf("missing launch effect contract for %s", fixture.effectID)
	}
	var routeFixture launchRouteFixture
	if launchTestEffectRequiresProviderRoute(fixture.effectID) {
		profile := launchProviderProfile(
			"digitalocean",
			contracts.LaunchConnectorDigitalOcean,
			"fra",
			"app-platform",
			[]string{"http_service", "static_site"},
			[]string{"health-check", "https-endpoint", "stateless-runtime"},
			[]string{contracts.LaunchLifecycleEphemeral},
			"digitalocean",
		)
		profile.Actions[0].ActionURN = contracts.LaunchProviderActionDigitalOceanActivate
		profile.Actions[1].ActionURN = contracts.LaunchProviderActionDigitalOceanProvision
		profile.Actions[2].ActionURN = contracts.LaunchProviderActionDigitalOceanRollback
		profile.Actions[3].ActionURN = contracts.LaunchProviderActionDigitalOceanTeardown
		routeFixture = singleLaunchRouteFixture(t, profile, true)
		bindLaunchInputToRoute(t, input, fixture.effectID, routeFixture)
	}
	if mutateInput != nil {
		mutateInput(input)
	}
	effectHash, err := contracts.DeriveLaunchEffectIdempotencyKey(fixture.effectID, input)
	if err != nil {
		t.Fatal(err)
	}
	now := launchRoutingNow
	verdictIssuedAt := now.Add(-time.Minute)
	verdictExpiry := now.Add(2 * time.Minute)
	permitIssuedAt := now
	permitExpiry := now.Add(45 * time.Second)
	dispatchDeadline := now.Add(40 * time.Second)
	schemaBytes, err := os.ReadFile(filepath.Join(repoRoot(t), "protocols", "json-schemas", filepath.FromSlash(fixture.schema)))
	if err != nil {
		t.Fatal(err)
	}
	principal := "spiffe://helm/data-plane-1"
	audience := "launch.dispatch"
	trustRootID := "kernel-root-1"
	authority, consumptionRef := launchApprovalAuthority(t, fixture.effectID, input, effectHash, now, principal, audience, trustRootID)
	envelope := contracts.LaunchEffectAuthorizationEnvelope{
		SchemaVersion:           contracts.LaunchEffectEnvelopeSchemaVersion,
		EffectID:                fixture.effectID,
		TenantID:                "tenant-1",
		WorkspaceID:             "workspace-1",
		MissionID:               "mission-1",
		Principal:               principal,
		Audience:                audience,
		KernelTrustRootID:       trustRootID,
		EffectOrdinal:           input["effect_ordinal"].(int),
		InputSchemaRef:          fixture.schema,
		InputSchemaHash:         canonicalize.ComputeArtifactHash(schemaBytes),
		Input:                   input,
		InputHash:               effectHash,
		IdempotencyKey:          effectHash,
		PlanHash:                input["plan_hash"].(string),
		ApprovalArtifactRef:     authority.Grant.GrantID,
		ApprovalArtifactHash:    authority.Grant.GrantHash,
		ApprovalConsumptionRef:  consumptionRef,
		ApprovalConsumptionHash: authority.Consumption.ConsumptionHash,
		DispatchAdmissionRef:    authority.DispatchAdmission.AdmissionID,
		DispatchAdmissionHash:   authority.DispatchAdmission.AdmissionHash,
		DependencySetRef:        fmt.Sprintf("dependency-set-%d", input["effect_ordinal"].(int)),
		DependencySetHash:       launchHash("7"),
		PolicyEpoch:             "epoch-1",
		EmergencyFenceEpoch:     4,
		Verdict:                 "ALLOW",
		KernelVerdictRef:        "verdict-1",
		KernelVerdictIssuedAt:   verdictIssuedAt.Format(time.RFC3339Nano),
		KernelVerdictExpiry:     verdictExpiry.Format(time.RFC3339Nano),
		KernelVerdictSignerKey:  "kernel-key-1",
		EffectPermitRef:         "permit-1",
		EffectPermitHash:        launchHash("0"),
		PermitNonce:             "0123456789abcdefABCDEF",
		PermitIssuedAt:          permitIssuedAt.Format(time.RFC3339Nano),
		PermitExpiry:            permitExpiry.Format(time.RFC3339Nano),
		ProofSessionRef:         "proof-session-1",
		EvidenceReservationRef:  "evidence-reservation-1",
		ConnectorID:             contract.ConnectorID,
		ConnectorContractHash:   input["connector_contract_hash"].(string),
		ConnectorAuthorityRef:   authority.Grant.ConnectorAuthority.BindingRef,
		ConnectorAuthorityHash:  authority.Grant.ConnectorAuthority.AuthorityHash,
		ActionURN:               contract.ActionURN,
		RequestBodyHash:         launchHash("1"),
		ArgsC14NHash:            launchHash("2"),
		DispatchDeadline:        dispatchDeadline.Format(time.RFC3339Nano),
		ReplayHint:              "single_use_permit",
	}
	privateKey := launchFixturePrivateKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	permit := launchPermitBinding(envelope, permitIssuedAt, permitExpiry, verdictIssuedAt, verdictExpiry, dispatchDeadline)
	var consumed atomic.Bool
	approvalPrivateKey := launchApprovalPrivateKey()
	approvalVerifier, err := approvalceremony.NewEd25519GrantSignatureVerifier(approvalPrivateKey.Public().(ed25519.PublicKey), "approval-key-1", trustRootID)
	if err != nil {
		t.Fatal(err)
	}
	ctx := contracts.LaunchEffectEnvelopeVerificationContext{
		Now: now,
		ResolveInputSchema: func(schemaRef string) ([]byte, error) {
			if schemaRef != envelope.InputSchemaRef {
				return nil, fmt.Errorf("unknown schema reference")
			}
			return append([]byte(nil), schemaBytes...), nil
		},
		ValidateInput: func(schemaRef, schemaHash string, candidate map[string]any) error {
			if schemaRef != envelope.InputSchemaRef || schemaHash != envelope.InputSchemaHash {
				return fmt.Errorf("unexpected schema identity")
			}
			return compileSchema(t, schemaRef).Validate(candidate)
		},
		ResolveApprovalAuthority: func(grantRef, grantHash, candidateConsumptionRef, consumptionHash string) (contracts.LaunchEffectApprovalAuthority, error) {
			if grantRef != authority.Grant.GrantID || grantHash != authority.Grant.GrantHash || candidateConsumptionRef != consumptionRef || consumptionHash != authority.Consumption.ConsumptionHash {
				return contracts.LaunchEffectApprovalAuthority{}, fmt.Errorf("approval authority not found")
			}
			return authority, nil
		},
		VerifyApprovalAuthority: func(candidate contracts.LaunchEffectApprovalAuthority) error {
			if err := approvalVerifier.VerifyGrantSignature(candidate.Grant, candidate.GrantSignatureAlgorithm, candidate.GrantSignature); err != nil {
				return err
			}
			if err := approvalVerifier.VerifyGrantConsumptionSignature(candidate.Consumption, candidate.ConsumptionSignatureAlgorithm, candidate.ConsumptionSignature); err != nil {
				return err
			}
			return approvalVerifier.VerifyDispatchAdmissionSignature(candidate.DispatchAdmission, candidate.DispatchSignatureAlgorithm, candidate.DispatchSignature)
		},
		VerifyDependencyState: func(ref, hash string) error {
			if ref != envelope.DependencySetRef || hash != envelope.DependencySetHash {
				return fmt.Errorf("dependency set mismatch")
			}
			return nil
		},
		ExpectedRequestBodyHash: envelope.RequestBodyHash,
		ExpectedArgsC14NHash:    envelope.ArgsC14NHash,
		ExpectedPolicyEpoch:     envelope.PolicyEpoch,
		MaximumPermitTTL:        45 * time.Second,
		ResolveVerdictKey: func(kernelTrustRootID, signerKeyID string) (ed25519.PublicKey, error) {
			if kernelTrustRootID != trustRootID || signerKeyID != envelope.KernelVerdictSignerKey {
				return nil, fmt.Errorf("unknown verdict signer key")
			}
			return publicKey, nil
		},
		ResolveEmergencyFence: func(tenantID, workspaceID string) (contracts.LaunchEmergencyFenceSnapshot, error) {
			return contracts.LaunchEmergencyFenceSnapshot{TenantID: tenantID, WorkspaceID: workspaceID, EffectiveEpoch: envelope.EmergencyFenceEpoch}, nil
		},
		FinalizeDispatch: func(expected contracts.LaunchEffectDispatchFinalization) (contracts.LaunchEffectDispatchFinalizationResult, error) {
			if expected.Permit != permit {
				return contracts.LaunchEffectDispatchFinalizationResult{}, fmt.Errorf("permit compare-and-swap binding mismatch")
			}
			if !now.Before(expected.MustCommitBefore) {
				return contracts.LaunchEffectDispatchFinalizationResult{}, fmt.Errorf("dispatch authority expired")
			}
			if !consumed.CompareAndSwap(false, true) {
				return contracts.LaunchEffectDispatchFinalizationResult{}, fmt.Errorf("permit already consumed")
			}
			return contracts.LaunchEffectDispatchFinalizationResult{CommittedAt: now}, nil
		},
		Permit: permit,
	}
	if launchTestEffectRequiresProviderRoute(fixture.effectID) {
		ctx.ResolveRouteBinding = func(routeRef string) (contracts.LaunchRouteBinding, error) {
			if routeRef != routeFixture.route.RouteID {
				return contracts.LaunchRouteBinding{}, fmt.Errorf("route not found")
			}
			return routeFixture.route, nil
		}
		ctx.RouteArtifacts = routeFixture.resolver
	}
	return envelope, ctx, privateKey, publicKey, routeFixture
}

func launchPermitBinding(envelope contracts.LaunchEffectAuthorizationEnvelope, issuedAt, expiry, verdictIssuedAt, verdictExpiry, deadline time.Time) contracts.LaunchEffectPermitBinding {
	return contracts.LaunchEffectPermitBinding{
		EffectPermitRef: envelope.EffectPermitRef, EffectPermitHash: envelope.EffectPermitHash, PermitNonce: envelope.PermitNonce,
		ProofSessionRef: envelope.ProofSessionRef, EvidenceReservationRef: envelope.EvidenceReservationRef,
		PermitIssuedAt: issuedAt, PermitExpiry: expiry, KernelVerdictRef: envelope.KernelVerdictRef, KernelVerdictHash: envelope.KernelVerdictHash,
		KernelVerdictIssuedAt: verdictIssuedAt, KernelVerdictExpiry: verdictExpiry,
		EffectID: envelope.EffectID, TenantID: envelope.TenantID, WorkspaceID: envelope.WorkspaceID, MissionID: envelope.MissionID,
		Principal: envelope.Principal, Audience: envelope.Audience, KernelTrustRootID: envelope.KernelTrustRootID, EffectOrdinal: envelope.EffectOrdinal,
		InputSchemaHash: envelope.InputSchemaHash, InputHash: envelope.InputHash, IdempotencyKey: envelope.IdempotencyKey, PlanHash: envelope.PlanHash,
		ApprovalArtifactRef: envelope.ApprovalArtifactRef, ApprovalArtifactHash: envelope.ApprovalArtifactHash,
		ApprovalConsumptionRef: envelope.ApprovalConsumptionRef, ApprovalConsumptionHash: envelope.ApprovalConsumptionHash,
		DispatchAdmissionRef: envelope.DispatchAdmissionRef, DispatchAdmissionHash: envelope.DispatchAdmissionHash,
		DependencySetRef: envelope.DependencySetRef, DependencySetHash: envelope.DependencySetHash,
		ConnectorID: envelope.ConnectorID, ConnectorContractHash: envelope.ConnectorContractHash,
		ConnectorAuthorityRef: envelope.ConnectorAuthorityRef, ConnectorAuthorityHash: envelope.ConnectorAuthorityHash,
		ActionURN: envelope.ActionURN, RequestBodyHash: envelope.RequestBodyHash, ArgsC14NHash: envelope.ArgsC14NHash,
		PolicyEpoch: envelope.PolicyEpoch, EmergencyFenceEpoch: envelope.EmergencyFenceEpoch, DispatchDeadline: deadline, SingleUse: true,
	}
}

func launchApprovalAuthority(t *testing.T, effectID string, input map[string]any, effectHash string, now time.Time, principal, audience, trustRootID string) (contracts.LaunchEffectApprovalAuthority, string) {
	t.Helper()
	planHash := input["plan_hash"].(string)
	policyHash := launchHash("6")
	action := launchTestApprovalAction(effectID)
	contract := contracts.LookupLaunchMissionEffectPreview(effectID)
	if contract == nil {
		t.Fatalf("missing launch effect contract for %s", effectID)
	}
	connectorID := contract.ConnectorID
	connectorAction := contract.ActionURN
	certificationRef := "cert:launch-internal-connector"
	certificationHash := launchHash("8")
	if launchTestProviderMutation(effectID) {
		var ok bool
		connectorID, ok = input["provider_connector_id"].(string)
		if !ok || connectorID == "" {
			t.Fatal("provider mutation fixture has no provider connector ID")
		}
		connectorAction, ok = input["provider_action_urn"].(string)
		if !ok || connectorAction == "" {
			t.Fatal("provider mutation fixture has no provider action")
		}
		certificationRef, ok = input["provider_certification_ref"].(string)
		if !ok || certificationRef == "" {
			t.Fatal("provider mutation fixture has no provider certification ref")
		}
		certificationHash, ok = input["provider_certification_hash"].(string)
		if !ok || certificationHash == "" {
			t.Fatal("provider mutation fixture has no provider certification hash")
		}
	}
	connectorAuthority, err := (contracts.ApprovalConnectorAuthority{
		SchemaVersion: contracts.ApprovalConnectorAuthoritySchemaV1, ContractVersion: contracts.ApprovalConnectorAuthorityContractV1,
		State: contracts.ApprovalConnectorAuthorityStateV1, BindingRef: "launch-connector-authority-" + effectID,
		TenantID: "tenant-1", WorkspaceID: "workspace-1", PackID: "mission-1", PackVersion: contracts.LaunchEffectCatalogVersion,
		PackManifestHash: planHash, Action: action, ConnectorAction: connectorAction, EffectHash: effectHash, PolicyHash: policyHash,
		ConnectorID: connectorID, ConnectorVersion: "1.0.0", ReleaseScopeKind: contracts.ConnectorReleaseAuthorityScopeGlobal,
		ReleaseAuthorityID: "launch-release-authority-" + effectID, ReleaseRegistryRevision: 1, ReleaseAuthorityHash: launchHash("3"),
		ConnectorExecutorKind: "digital", ConnectorBinaryHash: launchHash("a"), ConnectorSignatureRef: "sigstore://launch/connector/1.0.0",
		ConnectorSignatureHash: launchHash("b"), ConnectorSignerID: "mindburn-release", ConnectorSandboxProfile: "launch-provider-route-v1",
		ConnectorDriftPolicyRef: "policy://launch/connector-drift/v1", CertificationRef: certificationRef,
		CertificationHash: certificationHash, CertificationAuthority: "spiffe://helm/certification-service",
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := (contracts.ApprovalGrant{
		SchemaVersion: contracts.ApprovalGrantSchemaV1, ContractVersion: contracts.ApprovalGrantContractV1,
		GrantID: "launch-grant-" + effectID, TenantID: "tenant-1", WorkspaceID: "workspace-1", Audience: audience,
		PackID: "mission-1", PackVersion: contracts.LaunchEffectCatalogVersion, PackManifestHash: planHash,
		Action: action, ConnectorAuthority: connectorAuthority,
		IntentHash: planHash, EffectHash: effectHash, PlanHash: planHash, Decision: contracts.ApprovalGrantDecisionAllow,
		PolicyVersion: "policy-v1", PolicyEpoch: "epoch-1", PolicyHash: policyHash,
		ApprovalID: "launch-approval-" + effectID, CeremonyHash: launchHash("5"), SignerSetHash: launchHash("4"),
		ServerIdentity: "spiffe://helm/control-plane-1", KernelTrustRootID: trustRootID, SigningKeyRef: "approval-key-1",
		IssuedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(6 * time.Minute), Nonce: strings.Repeat("1", 64),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	consumption, err := (contracts.ApprovalGrantConsumption{
		SchemaVersion: contracts.ApprovalGrantConsumptionSchemaV1, ContractVersion: contracts.ApprovalGrantConsumptionContractV1,
		ApprovalID: grant.ApprovalID, GrantID: grant.GrantID, GrantHash: grant.GrantHash,
		TenantID: grant.TenantID, WorkspaceID: grant.WorkspaceID, Audience: grant.Audience, ConsumedBy: principal,
		PackID: grant.PackID, PackVersion: grant.PackVersion, PackManifestHash: grant.PackManifestHash,
		Action: grant.Action, ConnectorAuthority: grant.ConnectorAuthority, IntentHash: grant.IntentHash, EffectHash: grant.EffectHash, PlanHash: grant.PlanHash,
		PolicyVersion: grant.PolicyVersion, PolicyEpoch: grant.PolicyEpoch, PolicyHash: grant.PolicyHash,
		ServerIdentity: grant.ServerIdentity, KernelTrustRootID: grant.KernelTrustRootID, SigningKeyRef: grant.SigningKeyRef,
		GrantIssuedAt: grant.IssuedAt, GrantExpiresAt: grant.ExpiresAt, ConsumedAt: now.Add(-30 * time.Second),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := (contracts.ApprovalDispatchAdmission{
		SchemaVersion: contracts.ApprovalDispatchAdmissionSchemaV1, ContractVersion: contracts.ApprovalDispatchAdmissionContractV1,
		Coverage: contracts.ApprovalDispatchAdmissionCoverageV1, AdmissionID: "launch-dispatch-" + effectID, AttemptID: "permit-1",
		State: contracts.ApprovalDispatchAdmissionStateV1, ApprovalID: grant.ApprovalID, GrantID: grant.GrantID,
		GrantHash: grant.GrantHash, ConsumptionHash: consumption.ConsumptionHash, TenantID: grant.TenantID, WorkspaceID: grant.WorkspaceID,
		Audience: grant.Audience, AdmittedBy: principal, IdempotencyKeyHash: effectHash, EffectHash: effectHash,
		Action: grant.Action, ConnectorAuthority: grant.ConnectorAuthority, KernelTrustRootID: trustRootID, SigningKeyRef: grant.SigningKeyRef,
		IssuedAt: now.Add(-15 * time.Second), ExpiresAt: now.Add(45 * time.Second),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	privateKey := launchApprovalPrivateKey()
	grantPayload, err := approvalceremony.ApprovalGrantSigningPayload(grant, approvalceremony.GrantSignatureEd25519)
	if err != nil {
		t.Fatal(err)
	}
	consumptionPayload, err := approvalceremony.ApprovalGrantConsumptionSigningPayload(consumption, approvalceremony.GrantSignatureEd25519)
	if err != nil {
		t.Fatal(err)
	}
	admissionPayload, err := approvalceremony.ApprovalDispatchAdmissionSigningPayload(admission, approvalceremony.GrantSignatureEd25519)
	if err != nil {
		t.Fatal(err)
	}
	return contracts.LaunchEffectApprovalAuthority{
		Grant: grant, GrantSignatureAlgorithm: approvalceremony.GrantSignatureEd25519, GrantSignature: hex.EncodeToString(ed25519.Sign(privateKey, grantPayload)),
		Consumption: consumption, ConsumptionSignatureAlgorithm: approvalceremony.GrantSignatureEd25519, ConsumptionSignature: hex.EncodeToString(ed25519.Sign(privateKey, consumptionPayload)),
		DispatchAdmission: admission, DispatchSignatureAlgorithm: approvalceremony.GrantSignatureEd25519, DispatchSignature: hex.EncodeToString(ed25519.Sign(privateKey, admissionPayload)),
	}, "approval-consumption:" + grant.GrantID
}

func bindLaunchInputToRoute(t *testing.T, input map[string]any, effectID string, fixture launchRouteFixture) {
	t.Helper()
	placement := fixture.route.Placements[0]
	placementCost := fixture.quote.PlacementCosts[0]
	routeHash, err := contracts.DeriveLaunchRouteBindingHash(fixture.route)
	if err != nil {
		t.Fatal(err)
	}
	for field, value := range map[string]any{
		"provider":                         placement.ProviderID,
		"provider_account_ref":             placement.ProviderAccountRef,
		"provider_account_hash":            placement.ProviderAccountHash,
		"region":                           placement.RegionID,
		"jurisdiction":                     placement.Jurisdiction,
		"route_binding_ref":                fixture.route.RouteID,
		"route_binding_hash":               routeHash,
		"route_placement_id":               placement.PlacementID,
		"provider_capability_profile_ref":  placement.ProviderProfileRef,
		"provider_capability_profile_hash": placement.ProviderProfileHash,
		"provider_certification_ref":       placement.ProviderCertificationRef,
		"provider_certification_hash":      placement.ProviderCertificationHash,
		"provider_connector_id":            placement.ProviderConnectorID,
		"provider_connector_contract_hash": placement.ProviderConnectorContractHash,
		"repository_analysis_ref":          fixture.route.RepositoryAnalysisRef,
		"repository_analysis_hash":         fixture.route.RepositoryAnalysisHash,
		"workload_graph_ref":               fixture.route.WorkloadGraphRef,
		"workload_graph_hash":              fixture.route.WorkloadGraphHash,
		"resource_graph_ref":               fixture.route.ResourceGraphRef,
		"resource_graph_hash":              fixture.route.ResourceGraphHash,
		"route_quote_ref":                  fixture.route.RouteQuoteRef,
		"route_quote_hash":                 fixture.route.RouteQuoteHash,
		"quote_hash":                       fixture.route.RouteQuoteHash,
		"constraint_set_hash":              fixture.route.ConstraintSetHash,
		"generated_spec_hash":              fixture.route.GeneratedSpecHash,
		"gross_cap_minor":                  fixture.constraints.MaximumGrossMinor,
		"base_provider_cost_minor":         placementCost.BaseCostMinor,
		"tax_fx_reserve_minor":             placementCost.TaxFXReserveMinor,
		"gross_exposure_minor":             placementCost.GrossExposureMinor,
		"verified_credit_minor":            placementCost.VerifiedCreditMinor,
		"expected_cash_minor":              placementCost.ExpectedCashMinor,
		"currency":                         fixture.quote.Currency,
		"gross_cap_currency":               fixture.constraints.MaximumGrossCurrency,
		"credit_status":                    placementCost.CreditStatus,
		"price_snapshot_hash":              placementCost.PriceEvidenceHash,
		"provider_terms_profile_hash":      placementCost.TermsEvidenceHash,
		"credit_snapshot_hash":             placementCost.OfferSnapshotHash,
		"fx_snapshot_hash":                 fixture.quote.FXSnapshotHash,
		"tax_snapshot_hash":                fixture.quote.TaxSnapshotHash,
	} {
		setLaunchInputIfPresent(input, field, value)
	}
	if effectID == contracts.EffectTypeSpendAuthorize {
		return
	}
	for _, action := range placement.ActionBindings {
		if action.EffectID == effectID {
			setLaunchInputIfPresent(input, "provider_action_urn", action.ProviderActionURN)
			setLaunchInputIfPresent(input, "provider_payload_hash", action.ProviderPayloadHash)
			return
		}
	}
	t.Fatalf("route placement has no action binding for %s", effectID)
}

func setLaunchInputIfPresent(input map[string]any, field string, value any) {
	if _, ok := input[field]; ok {
		input[field] = value
	}
}

func launchTestProviderMutation(effectID string) bool {
	switch effectID {
	case contracts.EffectTypeProviderProvision, contracts.EffectTypeDeployProductionActivate, contracts.EffectTypeProviderRollback, contracts.EffectTypeProviderTeardown:
		return true
	default:
		return false
	}
}

func launchTestEffectRequiresProviderRoute(effectID string) bool {
	return effectID != contracts.EffectTypeCompanyArtifactUpdate
}

func launchTestApprovalAction(effectID string) string {
	switch effectID {
	case contracts.EffectTypeProviderProvision, contracts.EffectTypeSpendAuthorize:
		return contracts.ApprovalGrantActionInstall
	case contracts.EffectTypeDeployProductionActivate, contracts.EffectTypeCompanyArtifactUpdate:
		return contracts.ApprovalGrantActionUpgrade
	case contracts.EffectTypeProviderRollback:
		return contracts.ApprovalGrantActionRollback
	case contracts.EffectTypeProviderTeardown:
		return contracts.ApprovalGrantActionUninstall
	default:
		panic("unregistered launch effect")
	}
}

// Deterministic reference-pack material only; never register these keys in a
// runtime approval or verdict trust root.
func launchApprovalPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte("abcdef0123456789abcdef0123456789"))
}

func launchFixturePrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
}
