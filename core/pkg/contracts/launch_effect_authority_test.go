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

func TestLaunchEffectAuthorizationEnvelopeVerifiesEveryAuthorityBinding(t *testing.T) {
	envelope, ctx, _, publicKey := launchAuthorizationFixture(t)
	if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/launch_effect_envelope.v1.json"), envelope); err != nil {
		t.Fatalf("signed launch authorization envelope rejected by schema: %v", err)
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatalf("signed launch authorization envelope rejected: %v", err)
	}
	if envelope.KernelVerdictHash != "sha256:3c25da9dd9ac006c0d14ea6d6563f3733ff60276adb114689c20d4a3a254e5d6" {
		t.Fatalf("launch verdict hash = %s, want committed golden", envelope.KernelVerdictHash)
	}
	if envelope.KernelVerdictSignature != "ed25519:0424ab282768263a3d7247041a1e566d5177b3029488b7be73b64aa4b89bee125773efc0b99aae8f92078da18fc9c661c9ecbcd458f11e65b87ef6c7c4890e0a" {
		t.Fatalf("launch verdict signature = %s, want committed golden", envelope.KernelVerdictSignature)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("fixture public key is invalid")
	}
}

func TestLaunchEffectAuthorizationEnvelopeFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*contracts.LaunchEffectAuthorizationEnvelope, *contracts.LaunchEffectEnvelopeVerificationContext)
		resign bool
	}{
		{name: "outer input identity", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.TenantID = "tenant-cross-boundary"
		}},
		{name: "principal absent from consumed approval", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.Principal = "spiffe://helm/data-plane-other"
			ctx.Permit.Principal = envelope.Principal
		}},
		{name: "audience absent from approval", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.Audience = "launch.observe"
			ctx.Permit.Audience = envelope.Audience
		}},
		{name: "approval trust root", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.KernelTrustRootID = "kernel-root-other"
			ctx.Permit.KernelTrustRootID = envelope.KernelTrustRootID
		}},
		{name: "input schema hash", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.InputSchemaHash = launchHash("0")
		}},
		{name: "uppercase input schema hash", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.InputSchemaHash = "sha256:" + strings.Repeat("A", 64)
		}},
		{name: "missing schema validator", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ValidateInput = nil
		}},
		{name: "missing schema resolver", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveInputSchema = nil
		}},
		{name: "missing provider route resolver", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveRouteBinding = nil
		}},
		{name: "missing canonical approval resolver", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveApprovalAuthority = nil
		}},
		{name: "missing canonical approval verifier", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.VerifyApprovalAuthority = nil
		}},
		{name: "invalid canonical approval signature", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			original := ctx.ResolveApprovalAuthority
			ctx.ResolveApprovalAuthority = func(grantRef, grantHash, consumptionRef, consumptionHash string) (contracts.LaunchEffectApprovalAuthority, error) {
				authority, err := original(grantRef, grantHash, consumptionRef, consumptionHash)
				authority.GrantSignature = strings.Repeat("0", 128)
				return authority, err
			}
		}},
		{name: "invalid canonical dispatch admission signature", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			original := ctx.ResolveApprovalAuthority
			ctx.ResolveApprovalAuthority = func(grantRef, grantHash, consumptionRef, consumptionHash string) (contracts.LaunchEffectApprovalAuthority, error) {
				authority, err := original(grantRef, grantHash, consumptionRef, consumptionHash)
				authority.DispatchSignature = strings.Repeat("0", 128)
				return authority, err
			}
		}},
		{name: "connector release authority", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.ConnectorAuthorityHash = launchHash("0")
			ctx.Permit.ConnectorAuthorityHash = envelope.ConnectorAuthorityHash
		}},
		{name: "dispatch admission binding", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.DispatchAdmissionHash = launchHash("0")
			ctx.Permit.DispatchAdmissionHash = envelope.DispatchAdmissionHash
		}},
		{name: "dependency state", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.VerifyDependencyState = func(string, string) error { return fmt.Errorf("predecessor unresolved") }
		}},
		{name: "canonical input hash", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.InputHash = launchHash("0")
		}},
		{name: "idempotency key", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.IdempotencyKey = launchHash("0")
		}},
		{name: "effect permit hash", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.EffectPermitHash = launchHash("9")
		}},
		{name: "proof session", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.ProofSessionRef = "proof-session-other"
		}},
		{name: "evidence reservation", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.EvidenceReservationRef = "evidence-reservation-other"
		}},
		{name: "canonical request", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.RequestBodyHash = launchHash("0")
		}},
		{name: "connector action", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.ActionURN = contracts.LaunchActionProviderTeardown
		}},
		{name: "permit nonce", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.PermitNonce = "different_nonce_0123456789"
		}},
		{name: "noncanonical permit nonce", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.PermitNonce = "invalid.nonce.0123456789"
		}},
		{name: "policy epoch", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.PolicyEpoch = "epoch-stale"
		}},
		{name: "emergency fence", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.EmergencyFenceEpoch = 3
		}},
		{name: "dispatch after permit", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.DispatchDeadline = "2026-07-18T12:06:00Z"
		}},
		{name: "permit exceeds source-owned TTL", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.MaximumPermitTTL = 30 * time.Second
		}},
		{name: "expired verdict", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.Now = launchRoutingNow.Add(7 * time.Minute)
		}},
		{name: "untrusted verdict signer", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveVerdictKey = func(string) (ed25519.PublicKey, error) { return nil, fmt.Errorf("key absent from trust root") }
		}},
		{name: "missing atomic dispatch finalizer", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.FinalizeDispatch = nil
		}},
		{name: "active scoped stop at dispatch", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.FinalizeDispatch = func(contracts.LaunchEffectPermitBinding) error { return fmt.Errorf("scoped stop active") }
		}},
		{name: "signature", mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.KernelVerdictSignature = "ed25519:" + strings.Repeat("0", 128)
		}},
		{name: "uppercase signature encoding", mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.KernelVerdictSignature = "ed25519:" + strings.Repeat("A", 128)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope, ctx, privateKey, _ := launchAuthorizationFixture(t)
			test.mutate(&envelope, &ctx)
			if test.resign {
				var err error
				envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
				t.Fatal("authority-binding mutation was accepted")
			}
		})
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsContradictoryApprovedConnectorAction(t *testing.T) {
	envelope, ctx, verdictPrivateKey, _ := launchAuthorizationFixture(t)
	authority, err := ctx.ResolveApprovalAuthority(envelope.ApprovalArtifactRef, envelope.ApprovalArtifactHash, envelope.ApprovalConsumptionRef, envelope.ApprovalConsumptionHash)
	if err != nil {
		t.Fatal(err)
	}

	connectorAuthority := authority.Grant.ConnectorAuthority
	connectorAuthority.ConnectorAction = contracts.LaunchProviderActionDigitalOceanTeardown
	connectorAuthority.AuthorityHash = ""
	connectorAuthority, err = connectorAuthority.Seal()
	if err != nil {
		t.Fatal(err)
	}
	grant := authority.Grant
	grant.ConnectorAuthority = connectorAuthority
	grant.GrantHash = ""
	grant, err = grant.Seal()
	if err != nil {
		t.Fatal(err)
	}
	consumption := authority.Consumption
	consumption.GrantHash = grant.GrantHash
	consumption.ConnectorAuthority = connectorAuthority
	consumption.ConsumptionHash = ""
	consumption, err = consumption.Seal()
	if err != nil {
		t.Fatal(err)
	}
	admission := authority.DispatchAdmission
	admission.GrantHash = grant.GrantHash
	admission.ConsumptionHash = consumption.ConsumptionHash
	admission.ConnectorAuthority = connectorAuthority
	admission.AdmissionHash = ""
	admission, err = admission.Seal()
	if err != nil {
		t.Fatal(err)
	}

	approvalPrivateKey := launchApprovalPrivateKey()
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
	authority = contracts.LaunchEffectApprovalAuthority{
		Grant: grant, GrantSignatureAlgorithm: approvalceremony.GrantSignatureEd25519, GrantSignature: hex.EncodeToString(ed25519.Sign(approvalPrivateKey, grantPayload)),
		Consumption: consumption, ConsumptionSignatureAlgorithm: approvalceremony.GrantSignatureEd25519, ConsumptionSignature: hex.EncodeToString(ed25519.Sign(approvalPrivateKey, consumptionPayload)),
		DispatchAdmission: admission, DispatchSignatureAlgorithm: approvalceremony.GrantSignatureEd25519, DispatchSignature: hex.EncodeToString(ed25519.Sign(approvalPrivateKey, admissionPayload)),
	}

	envelope.ApprovalArtifactHash = grant.GrantHash
	envelope.ApprovalConsumptionHash = consumption.ConsumptionHash
	envelope.DispatchAdmissionHash = admission.AdmissionHash
	envelope.ConnectorAuthorityHash = connectorAuthority.AuthorityHash
	ctx.Permit.ApprovalArtifactHash = grant.GrantHash
	ctx.Permit.ApprovalConsumptionHash = consumption.ConsumptionHash
	ctx.Permit.DispatchAdmissionHash = admission.AdmissionHash
	ctx.Permit.ConnectorAuthorityHash = connectorAuthority.AuthorityHash
	ctx.ResolveApprovalAuthority = func(grantRef, grantHash, consumptionRef, consumptionHash string) (contracts.LaunchEffectApprovalAuthority, error) {
		if grantRef != grant.GrantID || grantHash != grant.GrantHash || consumptionRef != envelope.ApprovalConsumptionRef || consumptionHash != consumption.ConsumptionHash {
			return contracts.LaunchEffectApprovalAuthority{}, fmt.Errorf("approval authority not found")
		}
		return authority, nil
	}
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, verdictPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Permit.KernelVerdictHash = envelope.KernelVerdictHash

	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil || !strings.Contains(err.Error(), "connector action") {
		t.Fatalf("contradictory approved connector action was not rejected precisely: %v", err)
	}
}

func TestLaunchEffectAuthorizationRejectsUnsignedRouteProbes(t *testing.T) {
	envelope, ctx, _, _ := launchAuthorizationFixture(t)
	var routeReads atomic.Int32
	originalResolver := ctx.ResolveRouteBinding
	ctx.ResolveRouteBinding = func(routeRef string) (contracts.LaunchRouteBinding, error) {
		routeReads.Add(1)
		return originalResolver(routeRef)
	}
	envelope.KernelVerdictSignature = "ed25519:" + strings.Repeat("0", 128)
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
		t.Fatal("tampered Kernel verdict unexpectedly verified")
	}
	if routeReads.Load() != 0 {
		t.Fatal("source-owned route registry was queried before Kernel signature verification")
	}
}

func TestLaunchEffectAuthorizationEnvelopeConsumesPermitAtomically(t *testing.T) {
	envelope, ctx, _, _ := launchAuthorizationFixture(t)
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatalf("first dispatch verification failed: %v", err)
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
		t.Fatal("replayed launch effect permit was accepted")
	}
}

func TestLaunchEffectAuthorizationEnvelopeDoesNotConsumeAfterFailedVerification(t *testing.T) {
	envelope, ctx, _, _ := launchAuthorizationFixture(t)
	tampered := envelope
	tampered.KernelVerdictSignature = "ed25519:" + strings.Repeat("0", 128)
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(tampered, ctx); err == nil {
		t.Fatal("tampered verdict unexpectedly verified")
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatalf("failed verification consumed the permit: %v", err)
	}
}

func TestLaunchEffectAuthorizationEnvelopeVerifiesEveryPreviewEffect(t *testing.T) {
	for index, fixture := range launchInputFixtures() {
		index, fixture := index, fixture
		t.Run(fixture.effectID, func(t *testing.T) {
			envelope, ctx, _, _ := launchAuthorizationFixtureAt(t, index)
			if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/launch_effect_envelope.v1.json"), envelope); err != nil {
				t.Fatalf("launch authorization envelope rejected by schema: %v", err)
			}
			if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
				t.Fatalf("launch authorization envelope rejected: %v", err)
			}
		})
	}
}

func TestLaunchRollbackEnvelopeConsumesOnlyItsExactPreauthorization(t *testing.T) {
	envelope, ctx, privateKey, _ := launchAuthorizationFixtureAt(t, 3)
	envelope.ApprovalArtifactRef = "different-rollback-permit"
	envelope.ApprovalArtifactHash = launchHash("d")
	ctx.Permit.ApprovalArtifactRef = envelope.ApprovalArtifactRef
	ctx.Permit.ApprovalArtifactHash = envelope.ApprovalArtifactHash
	var err error
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Permit.KernelVerdictHash = envelope.KernelVerdictHash
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
		t.Fatal("rollback envelope accepted authority other than its exact nested rollback permit")
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsSchemaIncompleteCanonicalInput(t *testing.T) {
	envelope, ctx, privateKey, _ := launchAuthorizationFixture(t)
	envelope.Input = cloneLaunchInput(t, envelope.Input)
	delete(envelope.Input, "resource_graph_hash")
	key, err := contracts.DeriveLaunchEffectIdempotencyKey(envelope.EffectID, envelope.Input)
	if err != nil {
		t.Fatal(err)
	}
	envelope.InputHash = key
	envelope.IdempotencyKey = key
	ctx.Permit.InputHash = key
	ctx.Permit.IdempotencyKey = key
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
		t.Fatal("schema-incomplete canonical input passed the dispatch verifier")
	}
}

func launchAuthorizationFixture(t *testing.T) (contracts.LaunchEffectAuthorizationEnvelope, contracts.LaunchEffectEnvelopeVerificationContext, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	return launchAuthorizationFixtureAt(t, 0)
}

func launchAuthorizationFixtureAt(t *testing.T, fixtureIndex int) (contracts.LaunchEffectAuthorizationEnvelope, contracts.LaunchEffectEnvelopeVerificationContext, ed25519.PrivateKey, ed25519.PublicKey) {
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
	key, err := contracts.DeriveLaunchEffectIdempotencyKey(fixture.effectID, input)
	if err != nil {
		t.Fatal(err)
	}
	now := launchRoutingNow
	verdictIssuedAt := now.Add(-time.Minute)
	verdictExpiry := now.Add(2 * time.Minute)
	permitIssuedAt := now
	expiry := now.Add(45 * time.Second)
	deadline := now.Add(40 * time.Second)

	schemaBytes, err := os.ReadFile(filepath.Join(repoRoot(t), "protocols", "json-schemas", filepath.FromSlash(fixture.schema)))
	if err != nil {
		t.Fatal(err)
	}
	schemaHash := canonicalize.ComputeArtifactHash(schemaBytes)
	principal := "spiffe://helm/data-plane-1"
	audience := "launch.dispatch"
	trustRootID := "kernel-root-1"
	authority, approvalConsumptionRef := launchCanonicalApprovalAuthority(t, fixture.effectID, input, input["plan_hash"].(string), key, now, principal, audience, trustRootID)
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
		InputSchemaHash:         schemaHash,
		Input:                   input,
		InputHash:               key,
		IdempotencyKey:          key,
		PlanHash:                input["plan_hash"].(string),
		ApprovalArtifactRef:     authority.Grant.GrantID,
		ApprovalArtifactHash:    authority.Grant.GrantHash,
		ApprovalConsumptionRef:  approvalConsumptionRef,
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
		PermitExpiry:            expiry.Format(time.RFC3339Nano),
		ProofSessionRef:         "proof-session-1",
		EvidenceReservationRef:  "evidence-reservation-1",
		ConnectorID:             contract.ConnectorID,
		ConnectorContractHash:   input["connector_contract_hash"].(string),
		ConnectorAuthorityRef:   authority.Grant.ConnectorAuthority.BindingRef,
		ConnectorAuthorityHash:  authority.Grant.ConnectorAuthority.AuthorityHash,
		ActionURN:               contract.ActionURN,
		RequestBodyHash:         launchHash("1"),
		ArgsC14NHash:            launchHash("2"),
		DispatchDeadline:        deadline.Format(time.RFC3339Nano),
		ReplayHint:              "single_use_permit",
	}
	privateKey := launchFixturePrivateKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	permit := contracts.LaunchEffectPermitBinding{
		EffectPermitRef:         envelope.EffectPermitRef,
		EffectPermitHash:        envelope.EffectPermitHash,
		PermitNonce:             envelope.PermitNonce,
		ProofSessionRef:         envelope.ProofSessionRef,
		EvidenceReservationRef:  envelope.EvidenceReservationRef,
		PermitIssuedAt:          permitIssuedAt,
		PermitExpiry:            expiry,
		KernelVerdictRef:        envelope.KernelVerdictRef,
		KernelVerdictHash:       envelope.KernelVerdictHash,
		KernelVerdictIssuedAt:   verdictIssuedAt,
		KernelVerdictExpiry:     verdictExpiry,
		EffectID:                envelope.EffectID,
		TenantID:                envelope.TenantID,
		WorkspaceID:             envelope.WorkspaceID,
		MissionID:               envelope.MissionID,
		Principal:               envelope.Principal,
		Audience:                envelope.Audience,
		KernelTrustRootID:       envelope.KernelTrustRootID,
		EffectOrdinal:           envelope.EffectOrdinal,
		InputSchemaHash:         envelope.InputSchemaHash,
		InputHash:               envelope.InputHash,
		IdempotencyKey:          envelope.IdempotencyKey,
		PlanHash:                envelope.PlanHash,
		ApprovalArtifactRef:     envelope.ApprovalArtifactRef,
		ApprovalArtifactHash:    envelope.ApprovalArtifactHash,
		ApprovalConsumptionRef:  envelope.ApprovalConsumptionRef,
		ApprovalConsumptionHash: envelope.ApprovalConsumptionHash,
		DispatchAdmissionRef:    envelope.DispatchAdmissionRef,
		DispatchAdmissionHash:   envelope.DispatchAdmissionHash,
		DependencySetRef:        envelope.DependencySetRef,
		DependencySetHash:       envelope.DependencySetHash,
		ConnectorID:             envelope.ConnectorID,
		ConnectorContractHash:   envelope.ConnectorContractHash,
		ConnectorAuthorityRef:   envelope.ConnectorAuthorityRef,
		ConnectorAuthorityHash:  envelope.ConnectorAuthorityHash,
		ActionURN:               envelope.ActionURN,
		RequestBodyHash:         envelope.RequestBodyHash,
		ArgsC14NHash:            envelope.ArgsC14NHash,
		PolicyEpoch:             envelope.PolicyEpoch,
		EmergencyFenceEpoch:     envelope.EmergencyFenceEpoch,
		DispatchDeadline:        deadline,
		SingleUse:               true,
	}
	var consumed atomic.Bool
	approvalPrivateKey := launchApprovalPrivateKey()
	approvalPublicKey := approvalPrivateKey.Public().(ed25519.PublicKey)
	approvalVerifier, err := approvalceremony.NewEd25519GrantSignatureVerifier(approvalPublicKey, "approval-key-1", trustRootID)
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
		ResolveApprovalAuthority: func(grantRef, grantHash, consumptionRef, consumptionHash string) (contracts.LaunchEffectApprovalAuthority, error) {
			if grantRef != authority.Grant.GrantID || grantHash != authority.Grant.GrantHash || consumptionRef != approvalConsumptionRef || consumptionHash != authority.Consumption.ConsumptionHash {
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
		ResolveVerdictKey: func(signerKeyID string) (ed25519.PublicKey, error) {
			if signerKeyID != envelope.KernelVerdictSignerKey {
				return nil, fmt.Errorf("unknown verdict signer key")
			}
			return publicKey, nil
		},
		FinalizeDispatch: func(expected contracts.LaunchEffectPermitBinding) error {
			if expected != permit {
				return fmt.Errorf("permit compare-and-swap binding mismatch")
			}
			if !consumed.CompareAndSwap(false, true) {
				return fmt.Errorf("permit already consumed")
			}
			return nil
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
	return envelope, ctx, privateKey, publicKey
}

func launchCanonicalApprovalAuthority(t *testing.T, effectID string, input map[string]any, planHash, effectHash string, now time.Time, principal, audience, trustRootID string) (contracts.LaunchEffectApprovalAuthority, string) {
	t.Helper()
	action := launchTestApprovalAction(effectID)
	policyHash := launchHash("6")
	connectorAuthority := launchTestConnectorAuthority(t, effectID, input, planHash, effectHash, policyHash)
	grant, err := (contracts.ApprovalGrant{
		SchemaVersion: contracts.ApprovalGrantSchemaV1, ContractVersion: contracts.ApprovalGrantContractV1,
		GrantID: "launch-grant-" + effectID, TenantID: "tenant-1", WorkspaceID: "workspace-1", Audience: audience,
		PackID: "mission-1", PackVersion: contracts.LaunchEffectCatalogVersion, PackManifestHash: planHash, Action: action, ConnectorAuthority: connectorAuthority,
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
		PackID: grant.PackID, PackVersion: grant.PackVersion, PackManifestHash: grant.PackManifestHash, Action: grant.Action, ConnectorAuthority: grant.ConnectorAuthority,
		IntentHash: grant.IntentHash, EffectHash: grant.EffectHash, PlanHash: grant.PlanHash,
		PolicyVersion: grant.PolicyVersion, PolicyEpoch: grant.PolicyEpoch, PolicyHash: grant.PolicyHash,
		ServerIdentity: grant.ServerIdentity, KernelTrustRootID: grant.KernelTrustRootID, SigningKeyRef: grant.SigningKeyRef,
		GrantIssuedAt: grant.IssuedAt, GrantExpiresAt: grant.ExpiresAt, ConsumedAt: now.Add(-30 * time.Second),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := (contracts.ApprovalDispatchAdmission{
		SchemaVersion: contracts.ApprovalDispatchAdmissionSchemaV1, ContractVersion: contracts.ApprovalDispatchAdmissionContractV1,
		Coverage: contracts.ApprovalDispatchAdmissionCoverageV1, AdmissionID: "launch-dispatch-" + effectID, AttemptID: "permit-1", State: contracts.ApprovalDispatchAdmissionStateV1,
		ApprovalID: grant.ApprovalID, GrantID: grant.GrantID, GrantHash: grant.GrantHash, ConsumptionHash: consumption.ConsumptionHash,
		TenantID: grant.TenantID, WorkspaceID: grant.WorkspaceID, Audience: grant.Audience, AdmittedBy: principal,
		IdempotencyKeyHash: effectHash, EffectHash: effectHash, Action: grant.Action, ConnectorAuthority: grant.ConnectorAuthority,
		KernelTrustRootID: trustRootID, SigningKeyRef: grant.SigningKeyRef,
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

func launchTestConnectorAuthority(t *testing.T, effectID string, input map[string]any, planHash, effectHash, policyHash string) contracts.ApprovalConnectorAuthority {
	t.Helper()
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
		certificationRef, ok = input["provider_certification_ref"].(string)
		if !ok || certificationRef == "" {
			t.Fatal("provider mutation fixture has no provider certification ref")
		}
		certificationHash, ok = input["provider_certification_hash"].(string)
		if !ok || certificationHash == "" {
			t.Fatal("provider mutation fixture has no provider certification hash")
		}
		connectorAction, ok = input["provider_action_urn"].(string)
		if !ok || connectorAction == "" {
			t.Fatal("provider mutation fixture has no provider connector action")
		}
	}
	authority, err := (contracts.ApprovalConnectorAuthority{
		SchemaVersion: contracts.ApprovalConnectorAuthoritySchemaV1, ContractVersion: contracts.ApprovalConnectorAuthorityContractV1,
		State: contracts.ApprovalConnectorAuthorityStateV1, BindingRef: "launch-connector-authority-" + effectID,
		TenantID: "tenant-1", WorkspaceID: "workspace-1", PackID: "mission-1", PackVersion: contracts.LaunchEffectCatalogVersion,
		PackManifestHash: planHash, Action: launchTestApprovalAction(effectID), ConnectorAction: connectorAction, EffectHash: effectHash, PolicyHash: policyHash,
		ConnectorID: connectorID, ConnectorVersion: "1.0.0", ReleaseScopeKind: contracts.ConnectorReleaseAuthorityScopeGlobal,
		ReleaseAuthorityID: "launch-release-authority-" + effectID, ReleaseRegistryRevision: 1, ReleaseAuthorityHash: launchHash("3"),
		ConnectorExecutorKind: "digital", ConnectorBinaryHash: launchHash("a"),
		ConnectorSignatureRef: "sigstore://launch/connector/1.0.0", ConnectorSignatureHash: launchHash("b"), ConnectorSignerID: "mindburn-release",
		ConnectorSandboxProfile: "launch-provider-route-v1", ConnectorDriftPolicyRef: "policy://launch/connector-drift/v1",
		CertificationRef: certificationRef, CertificationHash: certificationHash, CertificationAuthority: "spiffe://helm/certification-service",
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func launchTestProviderMutation(effectID string) bool {
	switch effectID {
	case contracts.EffectTypeProviderProvision, contracts.EffectTypeDeployProductionActivate, contracts.EffectTypeProviderRollback, contracts.EffectTypeProviderTeardown:
		return true
	default:
		return false
	}
}

func bindLaunchInputToRoute(t *testing.T, input map[string]any, effectID string, fixture launchRouteFixture) {
	t.Helper()
	placement := fixture.route.Placements[0]
	placementCost := fixture.quote.PlacementCosts[0]
	routeHash, err := contracts.DeriveLaunchRouteBindingHash(fixture.route)
	if err != nil {
		t.Fatal(err)
	}
	setLaunchInputIfPresent(input, "provider", placement.ProviderID)
	setLaunchInputIfPresent(input, "provider_account_ref", placement.ProviderAccountRef)
	setLaunchInputIfPresent(input, "provider_account_hash", placement.ProviderAccountHash)
	setLaunchInputIfPresent(input, "region", placement.RegionID)
	setLaunchInputIfPresent(input, "jurisdiction", placement.Jurisdiction)
	setLaunchInputIfPresent(input, "route_binding_ref", fixture.route.RouteID)
	setLaunchInputIfPresent(input, "route_binding_hash", routeHash)
	setLaunchInputIfPresent(input, "route_placement_id", placement.PlacementID)
	setLaunchInputIfPresent(input, "provider_capability_profile_ref", placement.ProviderProfileRef)
	setLaunchInputIfPresent(input, "provider_capability_profile_hash", placement.ProviderProfileHash)
	setLaunchInputIfPresent(input, "provider_certification_ref", placement.ProviderCertificationRef)
	setLaunchInputIfPresent(input, "provider_certification_hash", placement.ProviderCertificationHash)
	setLaunchInputIfPresent(input, "provider_connector_id", placement.ProviderConnectorID)
	setLaunchInputIfPresent(input, "provider_connector_contract_hash", placement.ProviderConnectorContractHash)
	setLaunchInputIfPresent(input, "repository_analysis_ref", fixture.route.RepositoryAnalysisRef)
	setLaunchInputIfPresent(input, "repository_analysis_hash", fixture.route.RepositoryAnalysisHash)
	setLaunchInputIfPresent(input, "workload_graph_ref", fixture.route.WorkloadGraphRef)
	setLaunchInputIfPresent(input, "workload_graph_hash", fixture.route.WorkloadGraphHash)
	setLaunchInputIfPresent(input, "resource_graph_ref", fixture.route.ResourceGraphRef)
	setLaunchInputIfPresent(input, "resource_graph_hash", fixture.route.ResourceGraphHash)
	setLaunchInputIfPresent(input, "route_quote_ref", fixture.route.RouteQuoteRef)
	setLaunchInputIfPresent(input, "route_quote_hash", fixture.route.RouteQuoteHash)
	setLaunchInputIfPresent(input, "quote_hash", fixture.route.RouteQuoteHash)
	setLaunchInputIfPresent(input, "constraint_set_hash", fixture.route.ConstraintSetHash)
	setLaunchInputIfPresent(input, "generated_spec_hash", fixture.route.GeneratedSpecHash)
	setLaunchInputIfPresent(input, "gross_cap_minor", fixture.constraints.MaximumGrossMinor)
	setLaunchInputIfPresent(input, "base_provider_cost_minor", placementCost.BaseCostMinor)
	setLaunchInputIfPresent(input, "tax_fx_reserve_minor", placementCost.TaxFXReserveMinor)
	setLaunchInputIfPresent(input, "gross_exposure_minor", placementCost.GrossExposureMinor)
	setLaunchInputIfPresent(input, "verified_credit_minor", placementCost.VerifiedCreditMinor)
	setLaunchInputIfPresent(input, "expected_cash_minor", placementCost.ExpectedCashMinor)
	setLaunchInputIfPresent(input, "currency", fixture.quote.Currency)
	setLaunchInputIfPresent(input, "credit_status", placementCost.CreditStatus)
	setLaunchInputIfPresent(input, "price_snapshot_hash", placementCost.PriceEvidenceHash)
	setLaunchInputIfPresent(input, "provider_terms_profile_hash", placementCost.TermsEvidenceHash)
	setLaunchInputIfPresent(input, "credit_snapshot_hash", placementCost.OfferSnapshotHash)
	setLaunchInputIfPresent(input, "fx_snapshot_hash", fixture.quote.FXSnapshotHash)
	setLaunchInputIfPresent(input, "tax_snapshot_hash", fixture.quote.TaxSnapshotHash)
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

// launchApprovalPrivateKey is deterministic reference-pack material only; it
// must never be registered in a runtime approval trust root.
func launchApprovalPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte("abcdef0123456789abcdef0123456789"))
}

// launchFixturePrivateKey is deterministic reference-pack material only; it
// must never be registered in a runtime verdict trust root.
func launchFixturePrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
}
